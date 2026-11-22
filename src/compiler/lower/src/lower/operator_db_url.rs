//! The kernels that open the operator database agree with the runtime.
//!
//! [`super::reads_operator_db_url`] selects the `db-operator` runtime feature,
//! whose server start judges `DATABASE_URL`. A kernel that resolves the
//! operator store without the predicate would skip that start check; a
//! runtime caller of the resolver outside the known set would read
//! `DATABASE_URL` where no feature gate expects it.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use ipe_ir::KernelFn;

use super::{KernelUsage, reads_operator_db_url};

/// The runtime functions that resolve the operator store.
const RESOLVERS: [&str; 2] = ["operator_store", "check_operator_url_at_start"];

/// Every `.rs` file under `dir`, recursively.
fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// The name of the nearest `fn` declared on or before `lines`' last line.
fn enclosing_fn(lines: &[&str]) -> Option<String> {
    lines.iter().rev().find_map(|line| {
        let code = line.trim_start();
        let after = code.split_once("fn ")?.1;
        let name: String = after
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        (!name.is_empty() && !code.starts_with("//")).then_some(name)
    })
}

/// Every `(resolver, enclosing fn)` call pair in the runtime source.
fn resolver_callers() -> BTreeSet<(String, String)> {
    let runtime = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../runtime/rust/src");
    let mut files = Vec::new();
    rust_files(&runtime, &mut files);
    assert!(
        !files.is_empty(),
        "no runtime source under {}",
        runtime.display()
    );
    let mut callers = BTreeSet::new();
    for file in files {
        let Ok(text) = std::fs::read_to_string(&file) else {
            continue;
        };
        let lines: Vec<&str> = text.lines().collect();
        for (at, line) in lines.iter().enumerate() {
            let code = line.trim_start();
            if code.starts_with("//") {
                continue;
            }
            for resolver in RESOLVERS {
                let call = format!("{resolver}(");
                let definition = format!("fn {resolver}(");
                if code.contains(&call) && !code.contains(&definition) {
                    let caller = lines.get(..at).and_then(enclosing_fn).unwrap_or_default();
                    callers.insert((resolver.to_owned(), caller));
                }
            }
        }
    }
    callers
}

/// T17: the runtime callers of the operator resolvers are exactly
/// `db_connect`, `build_web_router` and `server_listen`, and the predicate holds
/// exactly for the kernels whose runtime symbol is `db_connect`.
#[test]
fn operator_url_readers_agree() {
    let want: BTreeSet<(String, String)> = [
        ("operator_store", "db_connect"),
        ("check_operator_url_at_start", "build_web_router"),
        ("check_operator_url_at_start", "server_listen"),
    ]
    .into_iter()
    .map(|(resolver, caller)| (resolver.to_owned(), caller.to_owned()))
    .collect();
    assert_eq!(resolver_callers(), want);

    let mut readers = 0;
    for kernel in KernelFn::all() {
        let opens_operator_store = kernel.def().runtime_fn == "db_connect";
        assert_eq!(
            reads_operator_db_url(kernel),
            opens_operator_store,
            "{kernel:?}"
        );
        readers += usize::from(opens_operator_store);
    }
    assert_eq!(readers, 1, "exactly `Db.connect` opens the operator store");
}

/// The usage scan records the operator flag, and it joins the saturation
/// check, so an early exit can never skip it.
#[test]
fn kernel_usage_records_the_operator_flag() {
    let mut usage = KernelUsage::default();
    usage.record(KernelFn::DbOpen);
    assert!(
        usage.db && !usage.db_operator,
        "`Db.open` is not an operator read"
    );
    usage.record(KernelFn::DbConnect);
    assert!(usage.db_operator, "`Db.connect` reads the operator store");

    let saturated = KernelUsage {
        db_operator: false,
        ..saturated_usage()
    };
    assert!(
        !saturated.all_set(),
        "an unset operator flag must keep the scan going"
    );
    assert!(saturated_usage().all_set());
}

/// A usage with every family flag set.
fn saturated_usage() -> KernelUsage {
    KernelUsage {
        db: true,
        tea: true,
        server: true,
        http: true,
        config: true,
        compression: true,
        csv: true,
        cache: true,
        encoding: true,
        regex: true,
        uuid: true,
        random: true,
        log: true,
        decimal: true,
        char_category: true,
        crypto_core: true,
        secret: true,
        json: true,
        crypto: true,
        jwt: true,
        url: true,
        ui: true,
        css: true,
        auth: true,
        web: true,
        tui: true,
        console: true,
        websocket: true,
        email: true,
        locale: true,
        time: true,
        env_public: true,
        db_operator: true,
        debug: true,
        ffi: true,
        async_runtime: true,
        ..KernelUsage::default()
    }
}
