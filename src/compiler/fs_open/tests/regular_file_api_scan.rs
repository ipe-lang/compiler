//! A proven file never hands out the raw handle it holds.
//!
//! [`RegularFile`] carries the proof that its handle is a regular file opened
//! without following a planted link, and [`CappedReader`] carries the read
//! ceiling over that handle. A raw `File` taken from either would outlive the
//! proof: a caller could read past the ceiling, or lock and rewrite the file
//! through an API the proof type never vetted. This scan parses every source
//! of the crate with `syn` and refuses, for each proof type: a public method
//! whose return type names `File`, a public field, and a conversion or borrow
//! trait impl that would expose the handle.
//!
//! [`RegularFile`]: ipe_fs_open::RegularFile
//! [`CappedReader`]: ipe_fs_open::CappedReader
#![forbid(unsafe_code)]

use syn::visit::{self, Visit};
use syn::{Fields, ImplItem, Item, ItemImpl, ItemStruct, PathSegment, Type, Visibility};

/// The types that hold a proven handle.
const PROOF_TYPES: [&str; 2] = ["RegularFile", "CappedReader"];

/// The raw handle type no proof type may hand out.
const RAW_HANDLE: &str = "File";

/// Traits whose impl on, or from, a proof type would expose its handle.
const EXPOSING_TRAITS: [&str; 16] = [
    "From",
    "Into",
    "AsRef",
    "AsMut",
    "Borrow",
    "BorrowMut",
    "Deref",
    "DerefMut",
    "AsFd",
    "AsRawFd",
    "IntoRawFd",
    "AsHandle",
    "AsRawHandle",
    "IntoRawHandle",
    "AsSocket",
    "AsRawSocket",
];

/// Whether `ty` names a path segment called `name` anywhere inside it.
fn names(ty: &Type, name: &str) -> bool {
    struct Finder<'n> {
        name: &'n str,
        found: bool,
    }
    impl<'ast> Visit<'ast> for Finder<'_> {
        fn visit_path_segment(&mut self, seg: &'ast PathSegment) {
            if seg.ident == self.name {
                self.found = true;
            }
            visit::visit_path_segment(self, seg);
        }
    }
    let mut finder = Finder { name, found: false };
    finder.visit_type(ty);
    finder.found
}

/// The proof type `ty` is, by its last path segment.
fn proof_type(ty: &Type) -> Option<&'static str> {
    let Type::Path(path) = ty else {
        return None;
    };
    let last = path.path.segments.last()?;
    PROOF_TYPES.into_iter().find(|name| last.ident == name)
}

/// What one source holds that the rule refuses, and the methods it found.
#[derive(Default)]
struct Scan {
    /// Every refused item, as a readable line.
    refused: Vec<String>,
    /// Every public method found on a proof type, as `Type::method`.
    methods: Vec<String>,
}

impl Scan {
    fn impl_block(&mut self, file: &str, block: &ItemImpl) {
        if let Some((trait_path, _)) = &block.trait_ {
            let Some(last) = trait_path.segments.last() else {
                return;
            };
            if !EXPOSING_TRAITS.iter().any(|t| last.ident == t) {
                return;
            }
            let on_proof = PROOF_TYPES.iter().any(|p| names(&block.self_ty, p));
            let from_proof = match &last.arguments {
                syn::PathArguments::AngleBracketed(args) => args.args.iter().any(|arg| {
                    matches!(arg, syn::GenericArgument::Type(t)
                        if PROOF_TYPES.iter().any(|p| names(t, p)))
                }),
                syn::PathArguments::None | syn::PathArguments::Parenthesized(_) => false,
            };
            if on_proof || from_proof {
                self.refused
                    .push(format!("{file}: impl {} touching a proof type", last.ident));
            }
            return;
        }
        let Some(owner) = proof_type(&block.self_ty) else {
            return;
        };
        for item in &block.items {
            let ImplItem::Fn(method) = item else {
                continue;
            };
            if !matches!(method.vis, Visibility::Public(_)) {
                continue;
            }
            self.methods.push(format!("{owner}::{}", method.sig.ident));
            if let syn::ReturnType::Type(_, ty) = &method.sig.output
                && names(ty, RAW_HANDLE)
            {
                self.refused.push(format!(
                    "{file}: pub fn {owner}::{} returns a raw handle",
                    method.sig.ident
                ));
            }
        }
    }

    fn struct_item(&mut self, file: &str, item: &ItemStruct) {
        if !PROOF_TYPES.iter().any(|p| item.ident == p) {
            return;
        }
        let public = match &item.fields {
            Fields::Named(named) => named
                .named
                .iter()
                .any(|f| !matches!(f.vis, Visibility::Inherited)),
            Fields::Unnamed(unnamed) => unnamed
                .unnamed
                .iter()
                .any(|f| !matches!(f.vis, Visibility::Inherited)),
            Fields::Unit => false,
        };
        if public {
            self.refused
                .push(format!("{file}: struct {} has a visible field", item.ident));
        }
    }

    fn items(&mut self, file: &str, items: &[Item]) {
        for item in items {
            match item {
                Item::Impl(block) => self.impl_block(file, block),
                Item::Struct(s) => self.struct_item(file, s),
                Item::Mod(module) => {
                    if let Some((_, inner)) = &module.content {
                        self.items(file, inner);
                    }
                }
                _ => {}
            }
        }
    }
}

/// Scan one source text.
#[allow(clippy::expect_used)] // a crate source or sample that does not parse is a broken test input
fn scan_source(file: &str, src: &str) -> Scan {
    let parsed = syn::parse_file(src).expect("crate source parses");
    let mut scan = Scan::default();
    scan.items(file, &parsed.items);
    scan
}

#[test]
fn no_proof_type_hands_out_its_raw_handle() {
    let src = e2e_support::manifest_dir!().join("src");
    let mut refused = Vec::new();
    let mut methods = Vec::new();
    for entry in std::fs::read_dir(&src).expect("read src/") {
        let path = entry.expect("src/ entry").path();
        if path.extension().is_none_or(|ext| ext != "rs") {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .expect("utf-8 source name")
            .to_owned();
        let text = std::fs::read_to_string(&path).expect("read source");
        let scan = scan_source(&name, &text);
        refused.extend(scan.refused);
        methods.extend(scan.methods);
    }
    assert!(
        methods.iter().any(|m| m == "RegularFile::read_bytes"),
        "the scan must see the proof type's methods: {methods:?}"
    );
    assert!(refused.is_empty(), "{refused:#?}");
}

#[test]
fn each_exposing_shape_is_refused() {
    let planted = [
        "impl RegularFile { pub const fn handle(&self) -> &File { &self.file } }",
        "impl RegularFile { pub fn handle_mut(&mut self) -> &mut std::fs::File { &mut self.file } }",
        "impl RegularFile { pub fn into_file(self) -> File { self.file } }",
        "impl RegularFile { pub fn try_handle(&self) -> Option<&File> { Some(&self.file) } }",
        "impl CappedReader { pub fn into_inner(self) -> std::io::Take<File> { self.inner } }",
        "impl AsRef<File> for RegularFile { fn as_ref(&self) -> &File { &self.file } }",
        "impl From<RegularFile> for File { fn from(f: RegularFile) -> File { f.file } }",
        "impl std::ops::Deref for RegularFile { type Target = File; fn deref(&self) -> &File { &self.file } }",
        "impl AsFd for RegularFile { fn as_fd(&self) -> BorrowedFd<'_> { self.file.as_fd() } }",
        "pub struct RegularFile { pub file: File, len: u64 }",
        "pub struct RegularFile { pub(crate) file: File, len: u64 }",
        "mod inner { impl RegularFile { pub fn handle(&self) -> &File { &self.file } } }",
    ];
    for src in planted {
        assert!(
            !scan_source("planted.rs", src).refused.is_empty(),
            "not refused: {src}"
        );
    }
    let admitted = [
        "impl RegularFile { pub fn id(&self) -> Result<FileId, OpenRefusal> { todo() } }",
        "impl RegularFile { fn handle(&self) -> &File { &self.file } }",
        "impl RegularFile { pub fn prove(file: File) -> Result<Self, OpenRefusal> { todo() } }",
        "impl Read for CappedReader { fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> { todo() } }",
    ];
    for src in admitted {
        assert!(
            scan_source("planted.rs", src).refused.is_empty(),
            "refused: {src}"
        );
    }
}
