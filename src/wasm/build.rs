//! Link the wasm32 shadow stack at the size `nesting.rs` declares.
//!
//! The wasm32 target links a 1 MiB shadow stack by default, too small for the
//! front end at the nesting ceiling, and an overflow there traps the module.
//! The linker argument is derived from
//! `ipe_diagnostics::nesting::WASM_SHADOW_STACK_BYTES`, never typed here, so the
//! linked stack and the ceiling's declared need cannot drift apart. Cargo applies
//! it to every artifact this package links, the test binaries included.
fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    #[allow(clippy::disallowed_methods)] // a build script reads cargo's own configuration
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH");
    if arch.is_ok_and(|arch| arch == "wasm32") {
        println!(
            "cargo::rustc-link-arg=-zstack-size={}",
            ipe_diagnostics::nesting::WASM_SHADOW_STACK_BYTES
        );
    }
}
