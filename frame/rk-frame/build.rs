//! Builds the vDSO of x86-64 from `vdso/x86_64.rs`, per spec/05-processes-signals-exec.md section
//! 5.4. rustc compiles the file and links it with `vdso/vdso.ld` to a shared object in `OUT_DIR`.
//! For each other target the file is empty, and the kernel maps no vDSO.

#![forbid(unsafe_code)]

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() -> Result<(), String> {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=vdso");
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap_or_default()).join("vdso.so");
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    if os != "none" || arch != "x86_64" {
        return std::fs::write(&out, [])
            .map_err(|e| format!("cannot write {}: {e}", out.display()));
    }
    let dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap_or_default()).join("vdso");
    let rustc = env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let script = dir.join("vdso.ld");
    // The link is a shared object, so the `-pie` of the target must go. `-z defs` makes a
    // reference to a function that is not in the vDSO an error. The vDSO has no relocations,
    // because the kernel does not relocate it.
    let link_args = [
        "-no-pie",
        "-shared",
        "-soname=linux-vdso.so.1",
        "--hash-style=both",
        "-zdefs",
        "-Bsymbolic",
        "--build-id=none",
    ];
    let mut cmd = Command::new(rustc);
    cmd.args(["--edition", "2024", "--target", "x86_64-unknown-none", "--crate-type", "bin"])
        .args(["--crate-name", "rk_vdso", "-D", "warnings"])
        .args(["-C", "opt-level=2", "-C", "panic=abort", "-C", "relocation-model=pic"])
        .args(["-C", "overflow-checks=off", "-C", "debuginfo=0"]);
    for arg in link_args {
        cmd.arg("-C").arg(format!("link-arg={arg}"));
    }
    cmd.arg("-C").arg(format!("link-arg=-T{}", script.display()));
    cmd.arg("-o").arg(&out).arg(dir.join("x86_64.rs"));
    // A build by cargo can set flags for the kernel target that do not fit the vDSO.
    cmd.env_remove("CARGO_ENCODED_RUSTFLAGS").env_remove("RUSTFLAGS");
    match cmd.status() {
        Ok(s) if s.success() => Ok(()),
        Ok(s) => Err(format!("the vDSO build failed: {s}")),
        Err(e) => Err(format!("cannot run rustc for the vDSO: {e}")),
    }
}
