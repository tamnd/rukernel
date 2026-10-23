//! Gives the linker script of the target architecture to the linker.

#![forbid(unsafe_code)]

fn main() {
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    if os == "none" && arch == "x86_64" {
        let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
        println!("cargo:rustc-link-arg-bins=-T{dir}/src/arch/x86_64.ld");
        // The kernel runs at a fixed address. The boot assembly uses absolute addresses, so the
        // image is not position independent. This flag is necessary when RUSTFLAGS replaces the
        // flags in .cargo/config.toml, as in CI.
        println!("cargo:rustc-link-arg-bins=-no-pie");
        println!("cargo:rerun-if-changed=src/arch/x86_64.ld");
    }
    println!("cargo:rerun-if-changed=build.rs");
}
