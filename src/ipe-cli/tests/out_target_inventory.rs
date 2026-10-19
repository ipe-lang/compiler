#![forbid(unsafe_code)]
//! Pins every `OutTarget::Path(` site of the `ipe` crate's source by file and argument text.
//!
//! A bare-path emission stamps its runtime bundle with the out role and keeps
//! the crate name of the environment; a test runner emitted that way would
//! share runtime units with hand-edited `out/` builds and build under a name
//! another crate may carry. The test runner is emitted only through
//! `OutTarget::Scratch`, so a new bare-path site must be added here on purpose.

#![cfg(not(target_arch = "wasm32"))]

/// Every `OutTarget::Path(` site: the file under `src/` and the argument text.
const SITES: &[(&str, &str)] = &[
    ("audit.rs", "&emitted_dir"),
    ("driver/build_pipeline.rs", "&out"),
    ("driver/build_pipeline.rs", "out_dir"),
    ("driver/build_pipeline.rs", "out_dir"),
    ("driver/build_pipeline.rs", "out_dir"),
    ("driver/commands_pkg.rs", "&out"),
    ("project_root/fixture.rs", "out_dir"),
];

/// The marker each site starts with.
const MARKER: &str = "OutTarget::Path(";

/// The argument text of every site in `text`: what lies between the marker and its closing paren.
fn arguments(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut rest = text;
    while let Some(at) = rest.find(MARKER) {
        let Some(after) = rest.get(at + MARKER.len()..) else {
            break;
        };
        let mut depth = 0_u32;
        let mut end = None;
        for (index, ch) in after.char_indices() {
            match ch {
                '(' => depth += 1,
                ')' if depth == 0 => {
                    end = Some(index);
                    break;
                }
                ')' => depth -= 1,
                _ => {}
            }
        }
        let argument = end.and_then(|end| after.get(..end)).unwrap_or(after);
        found.push(argument.split_whitespace().collect::<Vec<_>>().join(" "));
        rest = after;
    }
    found
}

#[test]
fn every_bare_path_emission_site_is_pinned() {
    let src = e2e_support::manifest_dir!().join("src");
    let files = panic_scan::rust_sources(&src, panic_scan::Want::RustFiles)
        .expect("the crate's source tree is listed whole");
    let mut sites = Vec::new();
    for path in files {
        let rel = path
            .strip_prefix(&src)
            .expect("a listed file lies under its root")
            .to_string_lossy()
            .replace('\\', "/");
        let text = std::fs::read_to_string(&path).expect("every listed source is readable");
        for argument in arguments(&text) {
            sites.push((rel.clone(), argument));
        }
    }
    sites.sort();
    let mut pinned: Vec<(String, String)> = SITES
        .iter()
        .map(|(file, argument)| ((*file).to_owned(), (*argument).to_owned()))
        .collect();
    pinned.sort();
    assert_eq!(
        sites, pinned,
        "a bare-path emission site changed; a test runner is emitted only through \
         `OutTarget::Scratch`"
    );
}

#[test]
fn the_argument_reader_reads_nested_parens() {
    assert_eq!(
        arguments("a OutTarget::Path(f(x)) b OutTarget::Path(&out)"),
        vec!["f(x)".to_owned(), "&out".to_owned()]
    );
}
