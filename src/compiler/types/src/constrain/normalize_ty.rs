use super::{
    BTreeMap, Builder, DResult, Diagnostic, RowTail, STAGE, Span, Symbol, Ty, TypeError, VarNamer,
    ty_to_doc,
};

impl Builder<'_> {
    /// Whether `ty` is the bare wildcard `any` annotation type.
    pub const fn is_wildcard_any_ty(ty: &Ty) -> bool {
        matches!(ty, Ty::Wildcard)
    }

    /// Whether an annotation type's final RETURN is the bare wildcard `any`.
    ///
    /// The return is what remains after peeling every leading `_ -> _` arrow.
    /// Such a binding's body is severed from its uses by the wildcard and must
    /// be re-tied — see [`Self::tie_wildcard_any_uses_to_bodies`].
    pub fn annotation_returns_wildcard_any(ty: &Ty) -> bool {
        let mut cur = ty;
        while let Ty::Fun(_, ret) = cur {
            cur = ret;
        }
        Self::is_wildcard_any_ty(cur)
    }

    /// Reduce a 2-arg `Task Error a` annotation type to the internal unary
    /// `Task a`, validating that the error channel is the `Error` type, and
    /// recursively normalise nested occurrences in any composite type.
    ///
    /// Ipê mandates `Task Error a` as the canonical user-facing form, but the
    /// type-checker's internal model is unary `Task a` — the error channel is
    /// always `Error` and therefore implicit in the IR.  This bridge is applied
    /// to every result of [`from_canon`] so user annotations unify with the
    /// kernel-built unary forms.
    ///
    /// # Errors
    ///
    /// Returns `IPE-T0001` when the error channel is not `Error` (e.g.
    /// `Task String a` or `Task Int a`).  Returns `IPE-T0016`
    /// ([`TypeError::TaskArity`]) when a `Task` annotation has a number of type
    /// arguments other than 1 or 2 — reachable from source (a bare `Task`, or
    /// `Task Error Int Bool`), because canonicalisation validates arity only for
    /// type *aliases*, never for a non-alias constructor application like `Task`.
    #[allow(clippy::too_many_lines)]
    pub fn normalize_annotation_ty(&self, ty: Ty, span: Span) -> DResult<Ty> {
        match ty {
            Ty::Con { module, name, args } => {
                if name == self.builtins.task {
                    match args.len() {
                        // 1-arg: already the internal unary form; recurse inside.
                        1 => {
                            let inner =
                                args.into_iter()
                                    .next()
                                    .ok_or_else(|| Diagnostic::CompilerBug {
                                        where_: STAGE,
                                        detail: "Task 1-arg: iterator exhausted (internal)".into(),
                                    })?;
                            let inner = self.normalize_annotation_ty(inner, span)?;
                            Ok(Ty::Con {
                                module,
                                name,
                                args: vec![inner],
                            })
                        }
                        // 2-arg: `Task Error a` — validate error channel, reduce.
                        2 => {
                            let mut it = args.into_iter();
                            let e_ty = it.next().ok_or_else(|| Diagnostic::CompilerBug {
                                where_: STAGE,
                                detail: "Task 2-arg: first arg missing (internal)".into(),
                            })?;
                            let a_ty = it.next().ok_or_else(|| Diagnostic::CompilerBug {
                                where_: STAGE,
                                detail: "Task 2-arg: second arg missing (internal)".into(),
                            })?;
                            if !self.is_error_ty(&e_ty) {
                                // Render both sides for a clear IPE-T0001 diagnostic.
                                let mut namer = VarNamer::new();
                                let expected = ty_to_doc(
                                    &Ty::Con {
                                        module: Vec::new(),
                                        name: self.builtins.error,
                                        args: Vec::new(),
                                    },
                                    self.interner,
                                    &mut namer,
                                )?;
                                let found = ty_to_doc(&e_ty, self.interner, &mut namer)?;
                                return Err(Diagnostic::Type {
                                    span,
                                    msg: TypeError::TypeMismatch {
                                        expected: Box::new(expected),
                                        found: Box::new(found),
                                        definition: None,
                                        path: Box::new([]),
                                    },
                                });
                            }
                            let inner = self.normalize_annotation_ty(a_ty, span)?;
                            Ok(Ty::Con {
                                module,
                                name,
                                args: vec![inner],
                            })
                        }
                        // A `Task` applied to any other arity (bare `Task`, or
                        // `Task Error Int Bool`) is ill-formed. It reaches here
                        // from source because canonicalisation validates arity
                        // only for type *aliases* (`NameError::AliasArity`), never
                        // for a non-alias type-constructor application like `Task`.
                        // Fail closed with a clean IPE-T0016 diagnostic naming the
                        // found argument count instead of raising a `CompilerBug`.
                        n => Err(Diagnostic::Type {
                            span,
                            msg: TypeError::TaskArity {
                                carrier: "Task",
                                found: n,
                            },
                        }),
                    }
                } else if (name == self.builtins.cmd || name == self.builtins.sub)
                    && args.len() != 1
                {
                    // `Cmd` / `Sub` take exactly one message type. A mis-arity
                    // application (bare `Cmd`, `Cmd Int Bool`) would otherwise
                    // reach the lowerer's `ir_type_from_canon` catch-all and
                    // ICE (IPE-I0001) — the Cmd/Sub sibling of the Task gate.
                    // Fail closed here with the same clean IPE-T0016, symmetric
                    // with the `Task` arm above.
                    let carrier = if name == self.builtins.cmd {
                        "Cmd"
                    } else {
                        "Sub"
                    };
                    Err(Diagnostic::Type {
                        span,
                        msg: TypeError::TaskArity {
                            carrier,
                            found: args.len(),
                        },
                    })
                } else if module.is_empty()
                    && args.is_empty()
                    && self.interner.resolve(name) == Some("HttpRequest")
                {
                    // `HttpRequest` is a stdlib type alias for a structural record
                    // (`{ body, headers, method, redirects, timeout, url }`).  The Rust port has no Ipê-source stdlib
                    // files, so the canonicaliser never registers `HttpRequest` as a
                    // type alias — it falls through to an opaque `Con`.  Expand it
                    // here so user annotations like `upstreamRequest : HttpRequest`
                    // unify with the structural record that kernels such as
                    // `HttpStreamOpen` / `HttpGet` / `HttpPost` expect.
                    //
                    // The `module.is_empty()` guard keys the match on the RESOLVED
                    // identity, not the bare name: only the empty-home builtin
                    // sentinel (`from_canon` copies `Type::Con.home`, empty for
                    // reserved/kernel builtins) expands. A user's own
                    // `type HttpRequest` — user-shadowable, carrying its real
                    // non-empty module home — is left intact so its ADT wins.
                    let mk = |n: Symbol| Ty::Con {
                        module: Vec::new(),
                        name: n,
                        args: Vec::new(),
                    };
                    let string = || mk(self.builtins.string);
                    let int = || mk(self.builtins.int);
                    let http_method_ty = || mk(self.builtins.http_method);
                    let redirect_policy_ty = || mk(self.builtins.redirect_policy);
                    let list = |t: Ty| Ty::Con {
                        module: Vec::new(),
                        name: self.builtins.list,
                        args: vec![t],
                    };
                    let mut req_fields = BTreeMap::new();
                    req_fields.insert(self.builtins.http_f_body, string());
                    req_fields.insert(
                        self.builtins.http_f_headers,
                        list(Ty::Tuple(vec![string(), string()])),
                    );
                    req_fields.insert(self.builtins.http_f_method, http_method_ty());
                    req_fields.insert(self.builtins.http_f_redirects, redirect_policy_ty());
                    req_fields.insert(self.builtins.http_f_timeout, int());
                    req_fields.insert(self.builtins.http_f_url, string());
                    Ok(Ty::Record(req_fields, RowTail::Closed))
                } else if module.is_empty()
                    && args.is_empty()
                    && self.interner.resolve(name) == Some("HttpResponse")
                {
                    // `HttpResponse` is a stdlib type alias for `{ body : String,
                    // headers : Dict String String, status : Int }`.  Expand for the
                    // same reason — and under the same empty-home identity guard —
                    // as `HttpRequest` above.
                    let mk = |n: Symbol| Ty::Con {
                        module: Vec::new(),
                        name: n,
                        args: Vec::new(),
                    };
                    let string = || mk(self.builtins.string);
                    let int = || mk(self.builtins.int);
                    let dict = |k: Ty, v: Ty| Ty::Con {
                        module: Vec::new(),
                        name: self.builtins.dict,
                        args: vec![k, v],
                    };
                    let mut resp_fields = BTreeMap::new();
                    resp_fields.insert(self.builtins.http_f_body, string());
                    resp_fields.insert(self.builtins.http_f_headers, dict(string(), string()));
                    resp_fields.insert(self.builtins.http_f_status, int());
                    Ok(Ty::Record(resp_fields, RowTail::Closed))
                } else if module.is_empty()
                    && args.is_empty()
                    && self.interner.resolve(name) == Some("Response")
                {
                    // `Ipe.Http.Server.Response` is a record alias
                    // `{ status : Int, body : String, headers : Dict String
                    // String, contentType : String }` (reference
                    // `Ipê/Http/Server.ipe:66`). Expand structurally — same
                    // mechanism and same empty-home identity guard as
                    // `HttpResponse` above — so a handler can build it as a record
                    // literal and read fields off it. A user's own qualified
                    // `Response` (non-empty module home) is not touched.
                    let mk = |n: Symbol| Ty::Con {
                        module: Vec::new(),
                        name: n,
                        args: Vec::new(),
                    };
                    let string = || mk(self.builtins.string);
                    let int = || mk(self.builtins.int);
                    let dict = |k: Ty, v: Ty| Ty::Con {
                        module: Vec::new(),
                        name: self.builtins.dict,
                        args: vec![k, v],
                    };
                    let mut resp_fields = BTreeMap::new();
                    resp_fields.insert(self.builtins.http_f_body, string());
                    resp_fields.insert(self.builtins.server_f_content_type, string());
                    resp_fields.insert(self.builtins.http_f_headers, dict(string(), string()));
                    resp_fields.insert(self.builtins.http_f_status, int());
                    Ok(Ty::Record(resp_fields, RowTail::Closed))
                } else if module.is_empty()
                    && args.is_empty()
                    && self.interner.resolve(name) == Some("Migration")
                {
                    // `Ipe.Db.Migration` is a record alias
                    // `{ name : String, sql : String }`. Expand structurally so a
                    // program can build migrations as record literals in a
                    // `List Migration`. `Migration` is user-shadowable, so the
                    // empty-home identity guard keeps a user's own `type Migration`
                    // (non-empty module home) from being expanded here.
                    let mk = |n: Symbol| Ty::Con {
                        module: Vec::new(),
                        name: n,
                        args: Vec::new(),
                    };
                    let string = || mk(self.builtins.string);
                    let mut m_fields = BTreeMap::new();
                    m_fields.insert(self.builtins.migration_f_name, string());
                    m_fields.insert(self.builtins.migration_f_sql, string());
                    Ok(Ty::Record(m_fields, RowTail::Closed))
                } else {
                    // Non-Task constructor: recurse into type arguments.
                    let args = args
                        .into_iter()
                        .map(|a| self.normalize_annotation_ty(a, span))
                        .collect::<DResult<Vec<_>>>()?;
                    Ok(Ty::Con { module, name, args })
                }
            }
            Ty::Fun(a, b) => {
                let a = self.normalize_annotation_ty(*a, span)?;
                let b = self.normalize_annotation_ty(*b, span)?;
                Ok(Ty::Fun(Box::new(a), Box::new(b)))
            }
            Ty::Tuple(elems) => {
                let elems = elems
                    .into_iter()
                    .map(|e| self.normalize_annotation_ty(e, span))
                    .collect::<DResult<Vec<_>>>()?;
                Ok(Ty::Tuple(elems))
            }
            Ty::Record(fields, tail) => {
                let fields = fields
                    .into_iter()
                    .map(|(k, v)| self.normalize_annotation_ty(v, span).map(|v| (k, v)))
                    .collect::<DResult<_>>()?;
                Ok(Ty::Record(fields, tail))
            }
            // Leaf types: pass through unchanged.
            other @ (Ty::Var(_) | Ty::Wildcard | Ty::Unit) => Ok(other),
        }
    }

    /// Check whether `ty` is the built-in `Error` type — a nullary type
    /// constructor named `"Error"`.  The module path is intentionally ignored so
    /// both bare `Error` and fully-qualified `Ipe.Error.Error` are accepted.
    pub fn is_error_ty(&self, ty: &Ty) -> bool {
        matches!(
            ty,
            Ty::Con { name, args, .. } if *name == self.builtins.error && args.is_empty()
        )
    }
}
