//! Regression test: every kernel's emit symbol must resolve to a real `pub fn`
//! in the runtime source (`src/**/*.rs`), OR appear in the explicit
//! `KNOWN_DEAD_OR_EPILOGUE` allowlist.
//!
//! **The emit symbol's source.** A kernel's emitted runtime function name is
//! defined once, in `ipe_kernels::StdlibKernel::def().runtime_fn` — the
//! emit-symbol SSOT. The backend's `naming::kernel_name(k)` is a zero-cost
//! projection of that field, so iterating `StdlibKernel::ALL` and reading
//! `def().runtime_fn` yields exactly the strings the backend emits.
//!
//! **Why this matters.** `callee_name()` in `emit_expr.rs` emits that symbol as a
//! bare Rust identifier in generated code.  A wrong name compiles fine in the Ipê
//! backend (it's just a string) but produces an `undefined` error when `cargo
//! build` runs on the generated project.  This test makes that class of bug a
//! failure of the test suite rather than a user-facing "cargo build failed"
//! surprise.
//!
//! **Allowlist rationale.**  Some `kernel_name()` entries are never reached by
//! the generic `callee_name()` path because dedicated emit functions intercept
//! those `KernelFn` variants first.  Their names in `naming.rs` are therefore
//! dead for the emit path; we keep them allowlisted rather than deleting them
//! so that future visitors understand the dispatch structure.  The epilogue entry
//! (`list_map_consume`) is defined inline in the generated-code preamble, not in
//! the runtime library.

use std::collections::HashSet;

/// Emit symbols never reached via the generic `callee_name()` path (a dedicated
/// emit function intercepts the variant first), OR defined in the generated-code
/// epilogue rather than the runtime.  See per-entry rationale below.
///
/// The `Store.*` accessor-intercept placeholder symbols are NOT listed here —
/// they are derived at test time from
/// [`ipe_kernels::StdlibKernel::ACCESSOR_INTERCEPT_PLACEHOLDERS`], the SSOT.
/// See the `every_kernel_name_resolves_to_runtime_fn` test body below.
const KNOWN_DEAD_OR_EPILOGUE: &[&str] = &[
    // ── Build-time: env_public embeds the whitelisted public environment
    //         values into the emitted binary at compile time; there is no
    //         runtime fn to resolve — the value is a baked constant. ──────────
    "env_public",
    // ── Dead: emit_task_retry_call constructs RetryPolicy / BackoffStrategy
    //         values inline for the builder variants; only task_retry_with has
    //         a real runtime fn. These name strings are never emitted. ────────
    "task_default_retry_policy",
    "task_exponential_backoff",
    "task_linear_backoff",
    "task_retry_on",
    "task_with_base_ms",
    "task_with_jitter",
    "task_with_max_attempts",
    "task_with_retry_on",
    // ── Dead: emit_http_builder_call constructs an HttpRequest struct inline
    //         for these variants; the name string is never used. ─────────────
    "http_default_request",
    "http_with_method",
    "http_with_body",
    "http_with_header",
    "http_with_timeout",
    // parity builders — same inline clone-and-reassign emission.
    "http_with_url",
    "http_with_redirects",
    // ── Dead: emit_expr's DbDefaultMigration arm emits the `Migration`
    //         record struct literal inline; this name string is never emitted.
    "db_default_migration",
    // ── Dead: emit_web_route generates a closure expression, not a function
    //         call. ──────────────────────────────────────────────────────────
    "web_route",
    // ── Dead: emit_web inlines install_web plus the app body, so the
    //         web_app_with descriptor name never reaches a runtime call. ──────
    "web_app_with",
    // ── Dead: emit_console_call synthesises the CLI entry-point block inline. ───
    "ipe_console_app_",
    // ── Dead: emit_worker_call synthesises the worker entry-point block inline. ─
    "ipe_worker_app_",
    // ── Dead: emit_ui_call emits ipe_runtime_rust::ui::render::ui_layout_with_vecs
    //         for UiLayoutWith; the bare "ui_layout_with" name is not used.
    //         Note: ui_layout_with_vecs IS in the runtime; this entry is for
    //         the stub "ui_layout_with" name that never reaches callee_name(). ──
    "ui_layout_with",
    // ── Epilogue: defined in the generated-code preamble (preamble.rs), not
    //         shipped as part of the runtime library. ─────────────────────────
    "list_map_consume",
    // ── Dead: `PubSub.topic : String -> Topic a` erases to the identity over
    //         the topic-name String; emit_expr emits the argument directly, so
    //         this name string never reaches a runtime call. ──────────────────
    "pubsub_topic",
    // (`js_send` / `js_subscribe` — the Ipe.Ffi.Js port transport — are REAL runtime
    // fns in `js_port.rs`, so they resolve and are deliberately NOT allowlisted.)
    // ── Dead: the config-tag ADT constructors (`Host.loopback` / `Level.warn`
    //         / `Web.strict` / …) are emitted inline as their raw `Int` tag by
    //         emit_config_ctor_call; these name strings never reach a runtime
    //         call. The setting builders they feed (`ipe_setting_host_bind` / …)
    //         ARE real runtime fns. ─────────────────────────────────────────────
    "config_host_mode_loopback",
    "config_host_mode_all_interfaces",
    "config_host_mode_env_driven",
    "config_log_level_debug",
    "config_log_level_info",
    "config_log_level_warn",
    "config_log_level_error",
    "config_csrf_mode_strict",
    "config_csrf_mode_inherit",
    "config_revocation_mode_off",
    "config_revocation_mode_store",
    // NOTE: The accessor-typed `Store.*` query leaves and column-spec builders
    // are omitted here.  Their `runtime_fn` name strings are derived at test
    // time from `ipe_kernels::StdlibKernel::ACCESSOR_INTERCEPT_PLACEHOLDERS`
    // (the SSOT) and unioned into the allowlist inside the test function below.
    // Adding them here a second time would create a parallel list that can
    // drift when a new placeholder kernel is added — exactly the problem the
    // SSOT is meant to prevent.
];

fn walk(dir: &std::path::Path, fn_re: &regex::Regex, out: &mut HashSet<String>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, fn_re, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs")
            && let Ok(content) = std::fs::read_to_string(&path)
        {
            for cap in fn_re.captures_iter(&content) {
                out.insert(cap[1].to_string());
            }
        }
    }
}

#[test]
fn every_kernel_name_resolves_to_runtime_fn() {
    let root = e2e_support::manifest_dir!();

    // ── 1. Collect every kernel's emit symbol from the SSOT ──────────────────
    // `StdlibKernel::def().runtime_fn` is the single source the backend's
    // `naming::kernel_name` projects; iterating `ALL` yields exactly the symbols
    // the emitted code names.
    let naming_symbols: HashSet<String> = ipe_kernels::StdlibKernel::ALL
        .iter()
        .map(|k| k.def().runtime_fn.to_string())
        .collect();
    assert!(
        !naming_symbols.is_empty(),
        "StdlibKernel::ALL is empty — the emit-symbol SSOT is broken"
    );

    // ── 2. Walk src/runtime/rust/src/**/*.rs: collect all `pub fn` names ─
    //    (`pub const fn` is also a callable runtime symbol — e.g. the nullary
    //    `term_color_*` colour constructors — so the pattern accepts `const`.)
    let runtime_src_dir = root.join("src");
    let mut runtime_fns: HashSet<String> = HashSet::new();
    let fn_re = regex::Regex::new(r"pub (?:const )?fn ([a-z_][a-z0-9_]*)").expect("fn_re");

    walk(&runtime_src_dir, &fn_re, &mut runtime_fns);
    assert!(
        !runtime_fns.is_empty(),
        "runtime pub-fn walk found zero functions — the runtime src path is broken"
    );

    // ── 3. Build the allowlist set ────────────────────────────────────────────
    // Seed from the static list, then union in the accessor-intercept placeholder
    // names derived from the SSOT (`StdlibKernel::ACCESSOR_INTERCEPT_PLACEHOLDERS`).
    // This means adding a 25th placeholder kernel only requires updating the SSOT
    // constant — this test and the point-free gate both update automatically.
    let mut allowlist: HashSet<String> = KNOWN_DEAD_OR_EPILOGUE
        .iter()
        .map(|s| s.to_string())
        .collect();
    for k in ipe_kernels::StdlibKernel::ACCESSOR_INTERCEPT_PLACEHOLDERS {
        allowlist.insert(k.def().runtime_fn.to_string());
    }

    // ── 4. Assert every kernel emit symbol is reachable ──────────────────────
    let mut unresolved: Vec<String> = naming_symbols
        .iter()
        .filter(|sym| !runtime_fns.contains(*sym) && !allowlist.contains(sym.as_str()))
        .cloned()
        .collect();
    unresolved.sort();

    assert_eq!(
        unresolved,
        Vec::<String>::new(),
        "kernel emit symbol(s) don't exist as `pub fn` in the runtime \
         AND aren't in KNOWN_DEAD_OR_EPILOGUE.\n\
         Fix: either (a) add/rename the runtime function, (b) fix the \
         `runtime_fn` in the kernel's `def()`, \
         or (c) add the symbol to KNOWN_DEAD_OR_EPILOGUE with a comment explaining why \
         the generic callee_name() path never reaches it.\n\
         Unresolved: {unresolved:?}"
    );
}

/// Reads every `.rs` file under `dir`, recursively.
fn read_sources(dir: &std::path::Path, out: &mut Vec<String>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            read_sources(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs")
            && let Ok(content) = std::fs::read_to_string(&path)
        {
            out.push(content);
        }
    }
}

/// The nesting-depth change `c` makes after `prev`; the `>` of `->` closes nothing.
const fn depth_step(prev: char, c: char) -> i32 {
    match c {
        '(' | '<' | '[' => 1,
        ')' | ']' => -1,
        '>' if prev != '-' => -1,
        _ => 0,
    }
}

/// Splits `s` at its top-level commas, trimming each part and dropping empty ones.
fn split_top_level(s: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut depth = 0;
    let mut prev = ' ';
    for c in s.chars() {
        depth += depth_step(prev, c);
        if c == ',' && depth == 0 {
            parts.push(std::mem::take(&mut current));
        } else {
            current.push(c);
        }
        prev = c;
    }
    parts.push(current);
    parts
        .into_iter()
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .collect()
}

/// Splits `s`, which opens with `open`, into the text inside that balanced group and the text after it.
fn balanced_group(s: &str, open: char) -> Option<(String, String)> {
    let body = s.strip_prefix(open)?;
    let mut depth = 1;
    let mut prev = open;
    for (at, c) in body.char_indices() {
        depth += depth_step(prev, c);
        if depth == 0 {
            let inside = body.get(..at)?;
            let after = body.get(at + c.len_utf8()..)?;
            return Some((inside.to_string(), after.to_string()));
        }
        prev = c;
    }
    None
}

/// The whitespace-normalised text of `rest` up to the fn body or `;`, line comments dropped.
fn fn_header(rest: &str) -> Option<String> {
    let mut header = String::new();
    let mut depth = 0;
    let mut prev = ' ';
    let mut in_comment = false;
    for c in rest.chars() {
        if in_comment {
            in_comment = c != '\n';
            continue;
        }
        if c == '/' && prev == '/' {
            header.pop();
            in_comment = true;
            prev = ' ';
            continue;
        }
        if depth == 0 && (c == '{' || c == ';') {
            return Some(header.split_whitespace().collect::<Vec<_>>().join(" "));
        }
        depth += depth_step(prev, c);
        header.push(c);
        prev = c;
    }
    None
}

/// The header of every `pub fn symbol` in `sources`, one per `cfg` variant.
///
/// A header spans the generics, parameters, return type, and where clause;
/// `None` marks a definition whose header could not be read.
fn runtime_fn_headers(sources: &[String], symbol: &str) -> Vec<Option<String>> {
    let pattern = format!(r"pub (?:const )?fn {}\b", regex::escape(symbol));
    let Ok(def_re) = regex::Regex::new(&pattern) else {
        return vec![None];
    };
    sources
        .iter()
        .flat_map(|content| {
            def_re
                .find_iter(content)
                .map(|m| content.get(m.end()..).and_then(fn_header))
        })
        .collect()
}

/// Trait bounds that make a generic parameter callable.
///
/// The `Fn` family, and `IntoServerHandler`, implemented for every
/// `Fn(ServerRequest) -> …` handler.
const CALLABLE_BOUND: &str = r"\b(?:Fn|FnMut|FnOnce)\(|\bIntoServerHandler<";

/// Whether each parameter of the runtime fn `header` is callable.
///
/// A parameter is callable when its type is `impl Fn…` / `dyn Fn…` (any of
/// `Fn` / `FnMut` / `FnOnce`), or a generic bounded by a [`CALLABLE_BOUND`].
fn callable_params(header: &str) -> Option<Vec<bool>> {
    let (generics, rest) = if header.starts_with('<') {
        balanced_group(header, '<')?
    } else {
        (String::new(), header.to_string())
    };
    let (params, tail) = balanced_group(rest.trim_start(), '(')?;
    let where_clause = tail.split_once("where").map_or("", |(_, w)| w);
    let callable_bound = regex::Regex::new(CALLABLE_BOUND).ok()?;
    let erased_fn = regex::Regex::new(r"\b(?:dyn|impl) (?:Fn|FnMut|FnOnce)\(").ok()?;
    let fn_bounded: HashSet<String> = split_top_level(&generics)
        .into_iter()
        .chain(split_top_level(where_clause))
        .filter_map(|g| {
            let (name, bound) = g.split_once(':')?;
            callable_bound
                .is_match(bound)
                .then(|| name.trim().to_string())
        })
        .collect();
    Some(
        split_top_level(&params)
            .iter()
            .filter_map(|p| p.split_once(':').map(|(_, ty)| ty.trim()))
            .map(|ty| {
                erased_fn.is_match(ty) || fn_bounded.contains(ty.trim_start_matches('&').trim())
            })
            .collect(),
    )
}

/// Which of a two-argument call's arguments is the function.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum FnPosition {
    First,
    Second,
}

/// Where an arity-2 Ipê scheme takes its function argument.
///
/// `None` when both or neither argument is a function.
const fn ipe_fn_position(shape: &ipe_kernels::TyShape) -> Option<FnPosition> {
    use ipe_kernels::TyShape;
    match shape {
        TyShape::Fun(first, TyShape::Fun(second, _)) => match (
            matches!(first, TyShape::Fun(..)),
            matches!(second, TyShape::Fun(..)),
        ) {
            (true, false) => Some(FnPosition::First),
            (false, true) => Some(FnPosition::Second),
            (true, true) | (false, false) => None,
        },
        _ => None,
    }
}

/// Where a kernel's runtime function must take its function argument.
const fn expected_runtime_position(ipe: FnPosition, order: ipe_kernels::ArgOrder) -> FnPosition {
    match (ipe, order) {
        (position, ipe_kernels::ArgOrder::IpeOrder) => position,
        (FnPosition::First, ipe_kernels::ArgOrder::ContainerFirst) => FnPosition::Second,
        (FnPosition::Second, ipe_kernels::ArgOrder::ContainerFirst) => FnPosition::First,
    }
}

/// How the definitions of a runtime function place its function parameter.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum RuntimeOrder {
    /// Every definition takes one function and one non-function, the function here.
    Resolved(FnPosition),
    /// No `pub fn` of that name in the runtime or the emitted-project template.
    Unresolvable,
    /// A definition whose parameters do not read as one function and one non-function.
    Unparsed,
    /// Definitions under different `cfg`s place the function differently.
    CfgVariantsDisagree,
}

/// The [`RuntimeOrder`] of `symbol` across every definition in `sources`.
fn runtime_order(sources: &[String], symbol: &str) -> RuntimeOrder {
    let positions: Option<Vec<FnPosition>> = runtime_fn_headers(sources, symbol)
        .iter()
        .map(
            |header| match callable_params(header.as_deref()?)?.as_slice() {
                [true, false] => Some(FnPosition::First),
                [false, true] => Some(FnPosition::Second),
                _ => None,
            },
        )
        .collect();
    let Some(positions) = positions else {
        return RuntimeOrder::Unparsed;
    };
    match positions.split_first() {
        Some((first, rest)) if rest.iter().all(|p| p == first) => RuntimeOrder::Resolved(*first),
        Some(_) => RuntimeOrder::CfgVariantsDisagree,
        None => RuntimeOrder::Unresolvable,
    }
}

/// Function-taking arity-2 kernels whose value a dedicated emitter builds inline, with no runtime fn.
///
/// The `Store.*` accessor placeholders join them from
/// `StdlibKernel::ACCESSOR_INTERCEPT_PLACEHOLDERS`. Adding an entry changes the
/// array length; an entry that gains a runtime fn, or no longer names such a
/// kernel, fails the test.
const NO_RUNTIME_FN_ARG_ORDER: [&str; 2] = ["task_retry_on", "task_with_retry_on"];

#[test]
fn declared_arg_order_matches_runtime_signature() {
    use ipe_kernels::StdlibKernel;

    let root = e2e_support::manifest_dir!();
    let mut sources = Vec::new();
    read_sources(&root.join("src"), &mut sources);
    let runtime_files = sources.len();
    read_sources(
        &root.join("../../compiler/backend/rust/templates"),
        &mut sources,
    );
    assert!(
        runtime_files > 0 && sources.len() > runtime_files,
        "the runtime or emitted-project template source walk found no files"
    );

    let no_runtime_fn: HashSet<&str> = NO_RUNTIME_FN_ARG_ORDER
        .into_iter()
        .chain(
            StdlibKernel::ACCESSOR_INTERCEPT_PLACEHOLDERS
                .iter()
                .map(|k| k.def().runtime_fn),
        )
        .collect();
    let mut exempted: HashSet<&str> = HashSet::new();
    let mut confirmed = 0_usize;
    let mut failures = Vec::new();
    for kernel in StdlibKernel::ALL {
        let def = kernel.def();
        if def.arity != 2 {
            continue;
        }
        let Some(shape) = def.shape else {
            failures.push(format!(
                "{kernel:?}: arity 2 with no scheme shape to place its function argument"
            ));
            continue;
        };
        let Some(ipe) = ipe_fn_position(shape) else {
            continue;
        };
        let expected = expected_runtime_position(ipe, def.arg_order);
        match runtime_order(&sources, def.runtime_fn) {
            RuntimeOrder::Resolved(found) if found == expected => confirmed += 1,
            RuntimeOrder::Resolved(found) => failures.push(format!(
                "{kernel:?}: declared {:?}, so `{}` must take its function {expected:?}, but \
                 takes it {found:?}",
                def.arg_order, def.runtime_fn
            )),
            RuntimeOrder::Unresolvable if no_runtime_fn.contains(def.runtime_fn) => {
                exempted.insert(def.runtime_fn);
            }
            other @ (RuntimeOrder::Unresolvable
            | RuntimeOrder::Unparsed
            | RuntimeOrder::CfgVariantsDisagree) => failures.push(format!(
                "{kernel:?}: `{}` is {other:?}, so its declared {:?} is unverified",
                def.runtime_fn, def.arg_order
            )),
        }
    }
    failures.extend(
        NO_RUNTIME_FN_ARG_ORDER
            .into_iter()
            .filter(|symbol| !exempted.contains(symbol))
            .map(|symbol| {
                format!(
                    "`{symbol}` in NO_RUNTIME_FN_ARG_ORDER names no function-taking arity-2 \
                     kernel without a runtime fn; remove it"
                )
            }),
    );
    assert!(
        confirmed > 0,
        "no kernel's argument order was confirmed against the runtime"
    );
    assert!(
        failures.is_empty(),
        "a function-taking arity-2 kernel's `ArgOrder` is not proven by its runtime function; \
         fix the row's `ArgOrder` in `StdlibKernel::identity` (the backend swaps and the \
         lowering walks reverse exactly the `ContainerFirst` rows) or the runtime signature:\n{}",
        failures.join("\n")
    );
}

/// How a runtime parameter receives a function value.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ParamCarrier {
    /// `impl Fn…`, `Box<dyn Fn…>`, or a generic with a [`CALLABLE_BOUND`]: an `Arc<dyn Fn>` is refused.
    Direct,
    /// `Arc<dyn Fn…>`: a stored function passes as is.
    Shared,
    /// A generic with no bound (a `cfg` stub variant): any value passes.
    Unconstrained,
    /// Not a callable type.
    NotCallable,
}

/// The [`ParamCarrier`] of each parameter of the runtime fn `header`.
fn param_carriers(header: &str) -> Option<Vec<ParamCarrier>> {
    let callable = callable_params(header)?;
    let (generics, rest) = if header.starts_with('<') {
        balanced_group(header, '<')?
    } else {
        (String::new(), header.to_string())
    };
    let (params, tail) = balanced_group(rest.trim_start(), '(')?;
    let where_clause = tail.split_once("where").map_or("", |(_, w)| w);
    let bounded: HashSet<String> = split_top_level(&generics)
        .into_iter()
        .chain(split_top_level(where_clause))
        .filter_map(|g| g.split_once(':').map(|(name, _)| name.trim().to_string()))
        .collect();
    let unbounded: HashSet<String> = split_top_level(&generics)
        .into_iter()
        .map(|g| g.trim().to_string())
        .filter(|g| !g.contains(':') && !bounded.contains(g))
        .collect();
    let types: Vec<String> = split_top_level(&params)
        .iter()
        .filter_map(|p| p.split_once(':').map(|(_, ty)| ty.trim().to_string()))
        .collect();
    if types.len() != callable.len() {
        return None;
    }
    Some(
        types
            .iter()
            .zip(callable)
            .map(|(ty, is_callable)| {
                match (is_callable, ty.contains("Arc<"), unbounded.contains(ty)) {
                    (false, _, true) => ParamCarrier::Unconstrained,
                    (false, _, false) => ParamCarrier::NotCallable,
                    (true, true, _) => ParamCarrier::Shared,
                    (true, false, _) => ParamCarrier::Direct,
                }
            })
            .collect(),
    )
}

/// The runtime parameter index an Ipê argument fills, past `leading` emit-supplied arguments.
const fn runtime_param_index(
    arg: usize,
    arity: u8,
    order: ipe_kernels::ArgOrder,
    leading: usize,
) -> usize {
    let ipe_index = match (order, arity, arg) {
        (ipe_kernels::ArgOrder::ContainerFirst, 2, 0) => 1,
        (ipe_kernels::ArgOrder::ContainerFirst, 2, 1) => 0,
        _ => arg,
    };
    ipe_index.saturating_add(leading)
}

/// What a kernel's emit arm does to its function argument before the runtime call.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum EmitWrap {
    /// Passed through as lowered.
    Verbatim,
    /// Re-wrapped in a fresh `move |x| (f)(x)` closure: either carrier calls through.
    Closure,
    /// Re-wrapped in `Arc::new(move |x| (f)(x))`: either carrier calls through.
    ArcClosure,
    /// Built with `Arc::new` (`wants_arc_ctor`): the lowered value must be a direct closure.
    ArcCtor,
}

/// The emit-side adaptation of a kernel's function argument.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct EmitAdapter {
    /// Arguments the emit arm supplies ahead of the Ipê arguments (an event name).
    leading: usize,
    wrap: EmitWrap,
}

const VERBATIM: EmitAdapter = EmitAdapter {
    leading: 0,
    wrap: EmitWrap::Verbatim,
};

/// Kernels whose emit arm adapts the function argument.
///
/// Mirrors `ipe_backend_rust`'s kernel-call arms (`StreamStream`,
/// `NativeUiEmit::OnSubmit`, the `HtmlEventShape::String` / `Bool` arms) and
/// `wants_arc_ctor` (the WebSocket server setters). The test refuses an entry the
/// verbatim rule already satisfies, so none outlives its need.
const EMIT_ADAPTERS: [(ipe_kernels::StdlibKernel, EmitAdapter); 11] = {
    use ipe_kernels::StdlibKernel as K;
    const CLOSURE: EmitAdapter = EmitAdapter {
        leading: 0,
        wrap: EmitWrap::Closure,
    };
    const NAMED_ARC_CLOSURE: EmitAdapter = EmitAdapter {
        leading: 1,
        wrap: EmitWrap::ArcClosure,
    };
    const ARC_CTOR: EmitAdapter = EmitAdapter {
        leading: 0,
        wrap: EmitWrap::ArcCtor,
    };
    [
        (K::StreamStream, CLOSURE),
        (K::UiOnSubmit, CLOSURE),
        (K::HtmlOnInput, NAMED_ARC_CLOSURE),
        (K::HtmlOnChange, NAMED_ARC_CLOSURE),
        (K::HtmlOnKeyDown, NAMED_ARC_CLOSURE),
        (K::HtmlOnKeyUp, NAMED_ARC_CLOSURE),
        (K::HtmlOnBool, NAMED_ARC_CLOSURE),
        (K::WsWithOnConnect, ARC_CTOR),
        (K::WsWithOnMessage, ARC_CTOR),
        (K::WsWithOnClose, ARC_CTOR),
        (K::WsWithOnError, ARC_CTOR),
    ]
};

/// Whether a scheme-derived slot carrier, adapted by `wrap`, is honoured by the runtime parameter it fills.
const fn carrier_agrees(
    slot: ipe_kernels::FnSlotCarrier,
    wrap: EmitWrap,
    param: ParamCarrier,
) -> bool {
    use EmitWrap as W;
    use ParamCarrier as P;
    use ipe_kernels::FnSlotCarrier as S;
    match (wrap, slot, param) {
        (_, _, P::Unconstrained)
        | (W::Verbatim, S::Direct, P::Direct)
        | (W::Verbatim, S::AcceptsShared, P::Shared)
        | (W::Closure, S::Direct | S::AcceptsShared, P::Direct)
        | (W::ArcClosure, S::Direct | S::AcceptsShared, P::Shared)
        | (W::ArcCtor, S::Direct, P::Shared) => true,
        (_, _, P::NotCallable)
        | (W::Verbatim, S::Direct, P::Shared)
        | (W::Verbatim, S::AcceptsShared, P::Direct)
        | (W::Closure, S::Direct | S::AcceptsShared, P::Shared)
        | (W::ArcClosure, S::Direct | S::AcceptsShared, P::Direct)
        | (W::ArcCtor, S::AcceptsShared, P::Shared)
        | (W::ArcCtor, S::Direct | S::AcceptsShared, P::Direct) => false,
    }
}

/// Whether each of `kernel`'s function `slots` agrees with the runtime fn `header`.
///
/// `Err` names a header this scan cannot read or a slot it cannot place.
fn slot_verdicts(
    kernel: ipe_kernels::StdlibKernel,
    slots: &[(usize, ipe_kernels::FnSlotCarrier)],
    header: &str,
    adapter: EmitAdapter,
) -> Result<Vec<bool>, String> {
    let def = kernel.def();
    let carriers = param_carriers(header).ok_or_else(|| {
        format!(
            "{kernel:?}: `{}` header unreadable: {header}",
            def.runtime_fn
        )
    })?;
    slots
        .iter()
        .map(|&(arg, slot)| {
            let index = runtime_param_index(arg, def.arity, def.arg_order, adapter.leading);
            carriers
                .get(index)
                .map(|&param| carrier_agrees(slot, adapter.wrap, param))
                .ok_or_else(|| {
                    format!(
                        "{kernel:?}: arg {arg} fills `{}` parameter {index}, which does not exist",
                        def.runtime_fn
                    )
                })
        })
        .collect()
}

/// Every function slot the scheme derives (`StdlibKernel::fn_slot_carrier`) is the
/// carrier the runtime parameter it fills takes, after its emit arm's adaptation.
///
/// A slot derived `Direct` whose runtime parameter is an `Arc<dyn Fn>` would have a
/// stored read eta-converted into a `Box` the parameter refuses; a slot derived
/// `AcceptsShared` whose parameter is an `impl Fn` would pass the `Arc` straight
/// into it. Both are exit-0-then-cargo-fail. A kernel whose runtime fn this source
/// scan cannot place is listed, never skipped; a kernel with no runtime fn (an
/// accessor-intercept placeholder, [`NO_RUNTIME_FN_ARG_ORDER`]) is skipped by name.
#[test]
fn derived_fn_slot_carrier_matches_runtime_signature() {
    use ipe_kernels::StdlibKernel;

    let root = e2e_support::manifest_dir!();
    let mut sources = Vec::new();
    read_sources(&root.join("src"), &mut sources);
    read_sources(
        &root.join("../../compiler/backend/rust/templates"),
        &mut sources,
    );
    let no_runtime_fn: HashSet<&str> = NO_RUNTIME_FN_ARG_ORDER
        .into_iter()
        .chain(
            StdlibKernel::ACCESSOR_INTERCEPT_PLACEHOLDERS
                .iter()
                .map(|k| k.def().runtime_fn),
        )
        .collect();
    let mut confirmed = 0_usize;
    let mut failures = Vec::new();
    let mut needed_adapters: Vec<StdlibKernel> = Vec::new();
    for &kernel in StdlibKernel::ALL {
        let def = kernel.def();
        let slots: Vec<(usize, ipe_kernels::FnSlotCarrier)> = (0..usize::from(def.arity))
            .filter_map(|arg| kernel.fn_slot_carrier(arg).map(|c| (arg, c)))
            .collect();
        if slots.is_empty() || no_runtime_fn.contains(def.runtime_fn) {
            continue;
        }
        let adapter = EMIT_ADAPTERS
            .iter()
            .find(|(k, _)| *k == kernel)
            .map_or(VERBATIM, |&(_, a)| a);
        let headers = runtime_fn_headers(&sources, def.runtime_fn);
        if headers.is_empty() {
            failures.push(format!(
                "{kernel:?}: `{}` has function slots {slots:?} but no runtime `pub fn`",
                def.runtime_fn
            ));
            continue;
        }
        for header in &headers {
            let Some(header) = header.as_deref() else {
                failures.push(format!(
                    "{kernel:?}: `{}` header unreadable",
                    def.runtime_fn
                ));
                continue;
            };
            match slot_verdicts(kernel, &slots, header, adapter) {
                Ok(verdicts) => {
                    for (&(arg, slot), agrees) in slots.iter().zip(verdicts) {
                        if agrees {
                            confirmed += 1;
                        } else {
                            failures.push(format!(
                                "{kernel:?}: arg {arg} derived {slot:?} under {adapter:?} \
                                 disagrees with `{}`: {header}",
                                def.runtime_fn
                            ));
                        }
                    }
                }
                Err(e) => failures.push(e),
            }
            let verbatim_fails = match slot_verdicts(kernel, &slots, header, VERBATIM) {
                Ok(verdicts) => verdicts.iter().any(|agrees| !agrees),
                Err(_) => true,
            };
            if adapter != VERBATIM && verbatim_fails {
                needed_adapters.push(kernel);
            }
        }
    }
    failures.extend(
        EMIT_ADAPTERS
            .iter()
            .filter(|(k, _)| !needed_adapters.contains(k))
            .map(|(k, _)| {
                format!(
                    "{k:?} in EMIT_ADAPTERS already agrees verbatim (or has no function slot); \
                     remove it"
                )
            }),
    );
    assert!(
        confirmed > 0,
        "no function slot was confirmed against the runtime"
    );
    assert!(
        failures.is_empty(),
        "a scheme-derived function slot carrier disagrees with its runtime parameter; fix \
         `StdlibKernel::fn_slot_carrier`, the kernel's emit arm, or `EMIT_ADAPTERS`:\n{}",
        failures.join("\n")
    );
}
