//! Builds the vDSO of x86-64 from `vdso/x86_64.rs` and the vDSO of arm64 from `vdso/aarch64.rs`,
//! per spec/05-processes-signals-exec.md section 5.4. rustc compiles the file and links it with
//! `vdso/vdso.ld` and the version script of the architecture to a shared object in `OUT_DIR`. For
//! each other target the file is empty, and the kernel maps no vDSO. On arm64 the build script
//! also writes the offset of `__kernel_rt_sigreturn` in the vDSO to `vdso_sigreturn.rs`, for the
//! signal code.

#![forbid(unsafe_code)]

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() -> Result<(), String> {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=vdso");
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").unwrap_or_default());
    let out = out_dir.join("vdso.so");
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let write = |path: PathBuf, data: &[u8]| {
        std::fs::write(&path, data).map_err(|e| format!("cannot write {}: {e}", path.display()))
    };
    let target = match arch.as_str() {
        "x86_64" if os == "none" => "x86_64-unknown-none",
        "aarch64" if os == "none" => "aarch64-unknown-none",
        _ => return write(out, &[]),
    };
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
    cmd.args(["--edition", "2024", "--target", target, "--crate-type", "bin"])
        .args(["--crate-name", "rk_vdso", "-D", "warnings"])
        .args(["-C", "opt-level=2", "-C", "panic=abort", "-C", "relocation-model=pic"])
        .args(["-C", "overflow-checks=off", "-C", "debuginfo=0"]);
    for arg in link_args {
        cmd.arg("-C").arg(format!("link-arg={arg}"));
    }
    cmd.arg("-C").arg(format!("link-arg=-T{}", script.display()));
    let version = dir.join(format!("{arch}.ver"));
    cmd.arg("-C").arg(format!("link-arg=--version-script={}", version.display()));
    cmd.arg("-o").arg(&out).arg(dir.join(format!("{arch}.rs")));
    // A build by cargo can set flags for the kernel target that do not fit the vDSO.
    cmd.env_remove("CARGO_ENCODED_RUSTFLAGS").env_remove("RUSTFLAGS");
    match cmd.status() {
        Ok(s) if s.success() => {}
        Ok(s) => return Err(format!("the vDSO build failed: {s}")),
        Err(e) => return Err(format!("cannot run rustc for the vDSO: {e}")),
    }
    if arch == "aarch64" {
        let image = std::fs::read(&out).map_err(|e| format!("{}: {e}", out.display()))?;
        let offset = symbol(&image, b"__kernel_rt_sigreturn")
            .ok_or("the vDSO has no __kernel_rt_sigreturn")?;
        write(out_dir.join("vdso_sigreturn.rs"), format!("{offset:#x}").as_bytes())?;
    }
    Ok(())
}

/// Reads the little endian value of `N` bytes at `at` in `b`.
fn le<const N: usize>(b: &[u8], at: usize) -> Option<u64> {
    let bytes = b.get(at..at.checked_add(N)?)?;
    Some(bytes.iter().rev().fold(0, |v, &x| v << 8 | u64::from(x)))
}

/// Finds the value of the dynamic symbol `name` in the ELF64 file `elf`. The vDSO is linked at
/// address 0, so the value is the offset in the file.
fn symbol(elf: &[u8], name: &[u8]) -> Option<u64> {
    let at = |v: u64| usize::try_from(v).ok();
    let (shoff, shentsize, shnum) = (at(le::<8>(elf, 0x28)?)?, 64, at(le::<2>(elf, 0x3c)?)?);
    let section = |i: usize| shoff.checked_add(i.checked_mul(shentsize)?);
    for i in 0..shnum {
        let sh = section(i)?;
        // SHT_DYNSYM. The link field is the section of the string table.
        if le::<4>(elf, sh + 4)? != 11 {
            continue;
        }
        let (off, size, entsize) =
            (at(le::<8>(elf, sh + 24)?)?, at(le::<8>(elf, sh + 32)?)?, at(le::<8>(elf, sh + 56)?)?);
        let strtab = at(le::<8>(elf, section(at(le::<4>(elf, sh + 40)?)?)? + 24)?)?;
        for sym in (off..off + size).step_by(entsize.max(1)) {
            let start = strtab + at(le::<4>(elf, sym)?)?;
            let end = start + elf.get(start..)?.iter().position(|&c| c == 0)?;
            if elf.get(start..end)? == name {
                return le::<8>(elf, sym + 8);
            }
        }
    }
    None
}
