//! Stamps the binary with the digest of its own extractor sources.
//!
//! The digest reaches the crate as `env!("IPE_INDEX_EXTRACTOR")`; an index
//! records it, and `update` rebuilds an index another build wrote.

use std::error::Error;
use std::path::PathBuf;

#[path = "src/extractor_digest.rs"]
mod extractor_digest;

fn main() -> Result<(), Box<dyn Error>> {
    for input in ["src", "Cargo.toml", "Cargo.lock", "build.rs"] {
        println!("cargo:rerun-if-changed={input}");
    }
    let digest = extractor_digest::extractor_digest(&PathBuf::from(env!("CARGO_MANIFEST_DIR")))?;
    println!("cargo:rustc-env=IPE_INDEX_EXTRACTOR={digest}");
    Ok(())
}
