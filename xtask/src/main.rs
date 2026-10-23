//! The build checks of rukernel.
//!
//! Each check is a command: `cargo xtask unsafe`, `layers`, `style`, `targets`, `boot-test`, `abi`
//! or `ci`.
//! The CI gate runs the same commands. Thus a check that passes on a developer machine passes in
//! CI. `cargo xtask qemu` boots the kernel for a person to use.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

/// The bare metal targets of the kernel, per spec/15-boot-and-platform.md section 15.1.
const KERNEL_TARGETS: &[&str] =
    &["x86_64-unknown-none", "aarch64-unknown-none", "riscv64gc-unknown-none-elf"];

/// The text files that the prose rules examine.
const TEXT_EXTENSIONS: &[&str] = &["md", "rs", "toml", "yml", "yaml", "txt"];

type Result<T = ()> = std::result::Result<T, String>;

struct Crate {
    name: String,
    dir: PathBuf,
    root: PathBuf,
}

fn main() -> ExitCode {
    let task = std::env::args().nth(1).unwrap_or_default();
    let result = match task.as_str() {
        "unsafe" => check_unsafe(),
        "layers" => check_layers(),
        "style" => check_style(),
        "targets" => build_targets(),
        "qemu" => qemu(&std::env::args().skip(2).collect::<Vec<_>>()),
        "boot-test" => boot_test(),
        "abi" => check_abi(),
        "ci" => ci(),
        _ => Err(String::from(
            "usage: cargo xtask <unsafe | layers | style | targets | qemu | boot-test | ci>\n\n\
             unsafe   each crate root forbids unsafe code, except the crates in xtask/unsafe-allowed.txt\n\
             layers   each crate depends only on its layer or a lower layer, per xtask/layers.txt\n\
             style    the prose has no em dashes, no en dashes and no horizontal rules\n\
             targets  the kernel crates build for the three bare metal targets\n\
             qemu     boot the x86-64 kernel in QEMU, with the arguments as the command line\n\
             boot-test  boot the x86-64 kernel in QEMU and check the self tests\n\
             abi      run rk-abigen on the pinned Linux tree and check that the output is in the tree\n\
             ci       all of the above except qemu and abi, and fmt, clippy, test and doc",
        )),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

fn workspace_root() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest.parent().map(Path::to_path_buf).unwrap_or(manifest)
}

fn read(path: &Path) -> Result<String> {
    fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))
}

/// Reads the workspace members from the root Cargo.toml.
fn crates() -> Result<Vec<Crate>> {
    let root = workspace_root();
    let manifest = read(&root.join("Cargo.toml"))?;
    let mut in_members = false;
    let mut crates = Vec::new();
    for line in manifest.lines() {
        let line = line.trim();
        if line.starts_with("members") {
            in_members = true;
            continue;
        }
        if in_members && line.starts_with(']') {
            break;
        }
        if in_members {
            let member = line.trim_matches(|c| c == '"' || c == ',' || c == ' ');
            if member.is_empty() || member.starts_with('#') {
                continue;
            }
            let dir = root.join(member);
            let name = package_name(&read(&dir.join("Cargo.toml"))?)
                .ok_or_else(|| format!("{member}/Cargo.toml: no package name"))?;
            let lib = dir.join("src/lib.rs");
            let root = if lib.exists() { lib } else { dir.join("src/main.rs") };
            crates.push(Crate { name, dir, root });
        }
    }
    Ok(crates)
}

fn package_name(manifest: &str) -> Option<String> {
    manifest
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with("name") && l.contains('='))
        .and_then(|l| l.split('"').nth(1))
        .map(String::from)
}

/// Reads a policy file: one entry on each line, `#` starts a comment.
fn policy(file: &str) -> Result<Vec<Vec<String>>> {
    let text = read(&workspace_root().join("xtask").join(file))?;
    Ok(text
        .lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .filter(|l| !l.is_empty())
        .map(|l| l.split_whitespace().map(String::from).collect())
        .collect())
}

fn check_unsafe() -> Result {
    let mut budgets = BTreeMap::new();
    let mut errors = Vec::new();
    for fields in policy("unsafe-allowed.txt")? {
        if let [name, budget] = fields.as_slice()
            && let Ok(budget) = budget.parse::<usize>()
        {
            budgets.insert(name.clone(), budget);
        } else {
            errors.push(format!("xtask/unsafe-allowed.txt: malformed line: {}", fields.join(" ")));
        }
    }
    let audited = read(&workspace_root().join("frame/AUDITED.md"))?;
    let crates = crates()?;
    for c in &crates {
        let Some(&budget) = budgets.get(&c.name) else {
            if !forbids_unsafe(&read(&c.root)?) {
                errors.push(format!(
                    "{}: the crate root does not have #![forbid(unsafe_code)]",
                    c.root.display()
                ));
            }
            continue;
        };
        if !audited.lines().any(|l| l.trim() == format!("## {}", c.name)) {
            errors.push(format!("frame/AUDITED.md: no section for {}", c.name));
        }
        let mut files = Vec::new();
        walk(&c.dir.join("src"), &mut files)?;
        let mut count = CodeCount::default();
        for file in files.iter().filter(|f| f.extension().is_some_and(|e| e == "rs")) {
            count.add(&read(file)?);
        }
        println!(
            "{}: {} lines of code, {} unsafe blocks, budget {budget} lines",
            c.name, count.lines, count.unsafe_blocks
        );
        if count.lines > budget {
            errors.push(format!(
                "{}: {} lines of code is over the budget of {budget}",
                c.name, count.lines
            ));
        }
    }
    let names: BTreeSet<&str> = crates.iter().map(|c| c.name.as_str()).collect();
    for name in budgets.keys() {
        if !names.contains(name.as_str()) {
            errors.push(format!("xtask/unsafe-allowed.txt: {name} is not a workspace crate"));
        }
    }
    report("unsafe rule", errors)
}

/// Tells if a crate root forbids unsafe code. The attribute must be on a line of its own.
fn forbids_unsafe(root: &str) -> bool {
    root.lines().any(|l| l.trim() == "#![forbid(unsafe_code)]")
}

/// The size of the Rust code of a crate.
#[derive(Debug, Default, PartialEq, Eq)]
struct CodeCount {
    /// The lines that are not blank and not only a comment.
    lines: usize,
    /// The `unsafe` blocks. An `unsafe fn` or an `unsafe impl` is not a block.
    unsafe_blocks: usize,
}

impl CodeCount {
    fn add(&mut self, text: &str) {
        for line in text.lines().map(str::trim) {
            if line.is_empty() || line.starts_with("//") {
                continue;
            }
            self.lines += 1;
            let code = line.split("//").next().unwrap_or("");
            self.unsafe_blocks += code.matches("unsafe {").count();
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Layer {
    Kernel(u32),
    Tool,
}

fn check_layers() -> Result {
    let mut layers = BTreeMap::new();
    let mut errors = Vec::new();
    for fields in policy("layers.txt")? {
        let [name, layer] = fields.as_slice() else {
            errors.push(format!("xtask/layers.txt: malformed line: {}", fields.join(" ")));
            continue;
        };
        let layer = match layer.as_str() {
            "tool" => Layer::Tool,
            n => match n.parse() {
                Ok(n) => Layer::Kernel(n),
                Err(_) => {
                    errors.push(format!("xtask/layers.txt: {name}: bad layer {n}"));
                    continue;
                }
            },
        };
        layers.insert(name.clone(), layer);
    }
    let crates = crates()?;
    let names: BTreeSet<&str> = crates.iter().map(|c| c.name.as_str()).collect();
    for c in &crates {
        let Some(&own) = layers.get(&c.name) else {
            errors.push(format!("{}: not in xtask/layers.txt", c.name));
            continue;
        };
        for dep in dependencies(&read(&c.dir.join("Cargo.toml"))?, &names) {
            let Some(&theirs) = layers.get(&dep) else { continue };
            let wrong = match (own, theirs) {
                (Layer::Tool, _) => false,
                (Layer::Kernel(_), Layer::Tool) => true,
                (Layer::Kernel(a), Layer::Kernel(b)) => b > a,
            };
            if wrong {
                errors.push(format!("{} depends on {dep}, which is in a higher layer", c.name));
            }
        }
    }
    report("layer rule", errors)
}

/// Finds the workspace crates in the dependency tables of a manifest.
fn dependencies(manifest: &str, names: &BTreeSet<&str>) -> Vec<String> {
    let mut in_deps = false;
    let mut deps = Vec::new();
    for line in manifest.lines().map(str::trim) {
        if line.starts_with('[') {
            in_deps = line.ends_with("dependencies]");
            continue;
        }
        if !in_deps {
            continue;
        }
        let key = line.split(['=', '.', ' ']).next().unwrap_or("");
        if names.contains(key) {
            deps.push(key.to_string());
        }
    }
    deps
}

fn check_style() -> Result {
    let root = workspace_root();
    let mut files = Vec::new();
    walk(&root, &mut files)?;
    let mut errors = Vec::new();
    for file in files {
        let text = read(&file)?;
        let shown = file.strip_prefix(&root).unwrap_or(&file).display().to_string();
        let markdown = file.extension().is_some_and(|e| e == "md");
        let mut in_code = false;
        for (n, line) in text.lines().enumerate() {
            if line.contains('\u{2014}') {
                errors.push(format!("{shown}:{}: em dash", n + 1));
            }
            if line.contains('\u{2013}') {
                errors.push(format!("{shown}:{}: en dash", n + 1));
            }
            if markdown {
                if line.trim_start().starts_with("```") {
                    in_code = !in_code;
                } else if !in_code && is_horizontal_rule(line) {
                    errors.push(format!("{shown}:{}: horizontal rule, use a heading", n + 1));
                }
            }
        }
    }
    report("prose rules", errors)
}

fn is_horizontal_rule(line: &str) -> bool {
    let chars: Vec<char> = line.chars().filter(|c| !c.is_whitespace()).collect();
    chars.len() >= 3 && matches!(chars[0], '-' | '*' | '_') && chars.iter().all(|&c| c == chars[0])
}

fn walk(dir: &Path, files: &mut Vec<PathBuf>) -> Result {
    let entries = fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for entry in entries {
        let path = entry.map_err(|e| e.to_string())?.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name == "target" || name == ".git" || name == "LICENSE" {
            continue;
        }
        if path.is_dir() {
            walk(&path, files)?;
        } else if path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| TEXT_EXTENSIONS.contains(&e))
        {
            files.push(path);
        }
    }
    Ok(())
}

fn kernel_crates() -> Result<Vec<String>> {
    Ok(policy("layers.txt")?
        .into_iter()
        .filter(|f| f.get(1).is_some_and(|l| l != "tool"))
        .filter_map(|f| f.into_iter().next())
        .collect())
}

fn build_targets() -> Result {
    let crates = kernel_crates()?;
    for target in KERNEL_TARGETS {
        let mut args = vec!["build", "--target", target];
        for c in &crates {
            args.extend(["-p", c.as_str()]);
        }
        cargo(&args)?;
    }
    Ok(())
}

/// The directories that rk-abigen writes.
const ABI_OUTPUT: &[&str] = &["abi", "core/rk-abi/src/generated"];

/// Runs rk-abigen and fails if its output is not the same as the files in the tree. The check
/// downloads the Linux tarball one time, so `ci` does not run it. CI runs it as its own job.
fn check_abi() -> Result {
    cargo(&["run", "--quiet", "--package", "rk-abigen", "--", "fetch"])?;
    cargo(&["run", "--quiet", "--package", "rk-abigen", "--", "generate"])?;
    let out = Command::new("git")
        .args(["status", "--porcelain", "--"])
        .args(ABI_OUTPUT)
        .current_dir(workspace_root())
        .output()
        .map_err(|e| format!("git: {e}"))?;
    let changed = String::from_utf8_lossy(&out.stdout);
    if !out.status.success() || !changed.trim().is_empty() {
        return Err(format!(
            "abi: the rk-abigen output is not the same as the tree. Commit the new output:\n{changed}"
        ));
    }
    println!("abi: ok");
    Ok(())
}

fn ci() -> Result {
    cargo(&["fmt", "--all", "--check"])?;
    check_unsafe()?;
    check_layers()?;
    check_style()?;
    cargo(&["clippy", "--workspace", "--all-targets", "--", "-D", "warnings"])?;
    cargo(&["test", "--workspace", "--no-fail-fast"])?;
    build_targets()?;
    boot_test()?;
    cargo(&["doc", "--workspace", "--no-deps"])?;
    println!("all checks passed");
    Ok(())
}

/// The QEMU exit status for a passed self test: `(0x10 << 1) | 1`, per kernel/rukernel/src/kernel.rs.
const QEMU_PASS: i32 = 33;

/// The longest time that one boot test can take. TCG on a slow CI runner is the slowest case.
const BOOT_TEST_TIMEOUT: Duration = Duration::from_secs(120);

/// The self tests that `boot-test` runs, each in its own boot.
const BOOT_TESTS: &[&str] = &[
    "boot",
    "trap",
    "mm",
    "heap",
    "timer",
    "initramfs",
    "syscall",
    "vm",
    "task",
    "fault",
    "init",
    "tty",
];

/// The self tests that `boot-test` runs again with the bzImage, through the Linux boot protocol.
const BZIMAGE_TESTS: &[&str] = &["boot", "mm", "initramfs", "init"];

/// A C compiler for the user test programs, and its flags for a static program and a static PIE
/// program.
struct UserCc {
    command: Vec<String>,
    static_flags: &'static [&'static str],
    pie_flags: &'static [&'static str],
}

/// Finds a C compiler that makes x86-64 Linux programs with musl. `RK_USER_CC` gives the command,
/// for example `musl-gcc` or `zig cc -target x86_64-linux-musl`. Then `musl-gcc` and `zig` are
/// tried. CI must have a compiler, so that CI does not skip the `init` test.
fn find_user_cc() -> Result<Option<UserCc>> {
    let works = |cmd: &str, arg: &str| {
        Command::new(cmd).arg(arg).stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok()
    };
    let gcc = |command: Vec<String>| UserCc {
        command,
        static_flags: &["-static"],
        pie_flags: &["-static-pie", "-fPIE"],
    };
    let zig = |command: Vec<String>| UserCc {
        command,
        static_flags: &["-static"],
        pie_flags: &["-static", "-fPIE"],
    };
    if let Ok(cc) = std::env::var("RK_USER_CC") {
        let command: Vec<String> = cc.split_whitespace().map(String::from).collect();
        let is_zig = command.first().is_some_and(|c| c.ends_with("zig"));
        return Ok(Some(if is_zig { zig(command) } else { gcc(command) }));
    }
    if works("musl-gcc", "--version") {
        return Ok(Some(gcc(vec![String::from("musl-gcc")])));
    }
    if works("zig", "version") {
        let command = ["zig", "cc", "-target", "x86_64-linux-musl"].map(String::from).to_vec();
        return Ok(Some(zig(command)));
    }
    if std::env::var_os("CI").is_some() {
        return Err(String::from("no C compiler for the user test programs, install musl-tools"));
    }
    Ok(None)
}

/// Compiles the user test program `name` from tests/user to `out`.
fn compile_user(cc: &UserCc, name: &str, pie: bool, out: &Path) -> Result {
    let src = workspace_root().join("tests/user").join(format!("{name}.c"));
    let flags = if pie { cc.pie_flags } else { cc.static_flags };
    let status = Command::new(&cc.command[0])
        .args(&cc.command[1..])
        .args(flags)
        .args(["-O2", "-s", "-Wall", "-Werror", "-o"])
        .arg(out)
        .arg(&src)
        .status()
        .map_err(|e| format!("{}: {e}", cc.command[0]))?;
    if !status.success() {
        return Err(format!("{}: the compiler failed with {status}", src.display()));
    }
    Ok(())
}

/// Builds the user test programs: init as a static program and hello as a static PIE program.
/// Gives `None` if there is no C compiler.
fn build_user(dir: &Path) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
    let (init, hello) = (dir.join("user-init"), dir.join("user-hello"));
    let Some(cc) = find_user_cc()? else {
        println!("user programs: skipped, no C compiler, set RK_USER_CC");
        let _ = fs::remove_file(&init);
        return Ok(None);
    };
    compile_user(&cc, "init", false, &init)?;
    compile_user(&cc, "hello", true, &hello)?;
    let read = |p: &Path| fs::read(p).map_err(|e| format!("{}: {e}", p.display()));
    Ok(Some((read(&init)?, read(&hello)?)))
}

/// Builds the x86-64 kernel and the initramfs of the boot tests, and gives the path of the ELF
/// image. The initramfs is in the same directory.
fn build_kernel() -> Result<PathBuf> {
    cargo(&["build", "--package", "rukernel", "--target", "x86_64-unknown-none"])?;
    let kernel = workspace_root().join("target/x86_64-unknown-none/debug/rukernel");
    let user = build_user(kernel.parent().ok_or("the kernel path has no directory")?)?;
    let initramfs = kernel.with_file_name("initramfs.cpio");
    fs::write(&initramfs, test_initramfs(user.as_ref()))
        .map_err(|e| format!("{}: {e}", initramfs.display()))?;
    Ok(kernel)
}

/// The initramfs that the `initramfs` and `init` self tests read, per
/// kernel/rukernel/src/selftest.rs and tests/user/init.c. With no user programs, `/init` is a
/// script that cannot run.
fn test_initramfs(user: Option<&(Vec<u8>, Vec<u8>)>) -> Vec<u8> {
    let mut w = rk_vfs::cpio::Writer::new();
    w.add(b".", 0o040_755, b"");
    w.add(b"etc", 0o040_755, b"");
    w.add_raw(100, b"etc/motd", 0o100_644, 2, (0, 0), b"");
    w.add_raw(100, b"etc/motd.link", 0o100_644, 2, (0, 0), b"rukernel initramfs\n");
    w.add(b"motd", 0o120_777, b"etc/motd");
    match user {
        Some((init, hello)) => {
            w.add(b"init", 0o100_755, init);
            w.add(b"bin", 0o040_755, b"");
            w.add(b"bin/hello", 0o100_755, hello);
        }
        None => w.add(b"init", 0o100_755, b"#!/bin/sh\n"),
    }
    w.finish()
}

/// The physical address where the loader puts the payload of the bzImage, and the kernel runs.
const BZIMAGE_LOAD: u64 = 0x10_0000;
/// The size of the setup part of the bzImage: the boot sector and 7 setup sectors.
const BZIMAGE_SETUP_SECTS: u8 = 7;
const BZIMAGE_SETUP_SIZE: usize = (BZIMAGE_SETUP_SECTS as usize + 1) * 512;

/// Reads a little endian integer of `N` bytes at `at`.
fn le<const N: usize>(b: &[u8], at: usize) -> Result<u64> {
    let bytes = b.get(at..at + N).ok_or("the ELF file is too short")?;
    Ok(bytes.iter().rev().fold(0, |v, &x| (v << 8) | u64::from(x)))
}

/// Writes the little endian integer `v` of `N` bytes at `at`.
fn put<const N: usize>(b: &mut [u8], at: usize, v: u64) {
    for (i, x) in b[at..at + N].iter_mut().enumerate() {
        *x = (v >> (8 * i)) as u8;
    }
}

/// Makes a bzImage from the kernel ELF file, per Documentation/arch/x86/boot.rst in the Linux
/// tree. The setup part is the `.rk_setup` section with the setup header. The payload is the
/// `PT_LOAD` segments as one flat image from `BZIMAGE_LOAD`.
fn bzimage(elf: &[u8]) -> Result<Vec<u8>> {
    if elf.get(..4) != Some(b"\x7fELF".as_slice()) || elf.get(4) != Some(&2) {
        return Err(String::from("the kernel is not an ELF64 file"));
    }
    let usize_of = |v: u64| usize::try_from(v).map_err(|e| e.to_string());

    let (phoff, phentsize, phnum) =
        (usize_of(le::<8>(elf, 0x20)?)?, usize_of(le::<2>(elf, 0x36)?)?, le::<2>(elf, 0x38)?);
    let mut segments = Vec::new();
    for i in 0..usize_of(phnum)? {
        let ph = phoff + i * phentsize;
        if le::<4>(elf, ph)? == 1 {
            let offset = usize_of(le::<8>(elf, ph + 8)?)?;
            let (paddr, filesz, memsz) =
                (le::<8>(elf, ph + 24)?, le::<8>(elf, ph + 32)?, le::<8>(elf, ph + 40)?);
            if paddr < BZIMAGE_LOAD {
                return Err(format!("a segment is at {paddr:#x}, below {BZIMAGE_LOAD:#x}"));
            }
            segments.push((offset, paddr, filesz, memsz));
        }
    }
    let file_end = segments.iter().map(|s| s.1 + s.2).max().ok_or("the kernel has no segments")?;
    let mem_end = segments.iter().map(|s| s.1 + s.3).max().unwrap_or(file_end);
    let mut payload = vec![0; usize_of(file_end - BZIMAGE_LOAD)?.next_multiple_of(PE_FILE_ALIGN)];
    for &(offset, paddr, filesz, _) in &segments {
        let (at, len) = (usize_of(paddr - BZIMAGE_LOAD)?, usize_of(filesz)?);
        let data = elf.get(offset..offset + len).ok_or("a segment is outside the file")?;
        payload[at..at + len].copy_from_slice(data);
    }

    let (shoff, shentsize, shnum, shstrndx) = (
        usize_of(le::<8>(elf, 0x28)?)?,
        usize_of(le::<2>(elf, 0x3a)?)?,
        usize_of(le::<2>(elf, 0x3c)?)?,
        usize_of(le::<2>(elf, 0x3e)?)?,
    );
    let strtab = usize_of(le::<8>(elf, shoff + shstrndx * shentsize + 0x18)?)?;
    let mut setup = None;
    for i in 0..shnum {
        let sh = shoff + i * shentsize;
        let name = strtab + usize_of(le::<4>(elf, sh)?)?;
        if elf.get(name..name + 10) == Some(b".rk_setup\0".as_slice()) {
            let (offset, size) =
                (usize_of(le::<8>(elf, sh + 0x18)?)?, usize_of(le::<8>(elf, sh + 0x20)?)?);
            setup = elf.get(offset..offset + size);
        }
    }
    let setup = setup.ok_or("the kernel has no .rk_setup section")?;
    if setup.len() > BZIMAGE_SETUP_SIZE - 0x200 {
        return Err(format!(
            "the setup code is {} bytes, more than {}",
            BZIMAGE_SETUP_SIZE - 0x200,
            setup.len()
        ));
    }

    let mut image = vec![0; BZIMAGE_SETUP_SIZE];
    image[..setup.len()].copy_from_slice(setup);
    image[0x1f1] = BZIMAGE_SETUP_SECTS;
    put::<4>(&mut image, 0x1f4, payload.len() as u64 / 16); // syssize
    put::<2>(&mut image, 0x1fa, 0xffff); // vid_mode: normal
    put::<2>(&mut image, 0x1fe, 0xaa55); // boot_flag
    image[0x200..0x202].copy_from_slice(&[0xeb, 0x7e]); // jmp to the setup code at 0x280
    image[0x202..0x206].copy_from_slice(b"HdrS");
    put::<2>(&mut image, 0x206, 0x020f); // the protocol version 2.15
    image[0x211] = 0x01; // loadflags: LOADED_HIGH
    put::<2>(&mut image, 0x212, 0x8000); // setup_move_size
    put::<4>(&mut image, 0x214, BZIMAGE_LOAD); // code32_start
    put::<4>(&mut image, 0x22c, 0x7fff_ffff); // initrd_addr_max
    put::<4>(&mut image, 0x230, 0x20_0000); // kernel_alignment
    put::<2>(&mut image, 0x236, 0x0001); // xloadflags: XLF_KERNEL_64
    put::<4>(&mut image, 0x238, 2047); // cmdline_size
    put::<8>(&mut image, 0x258, BZIMAGE_LOAD); // pref_address
    put::<4>(&mut image, 0x260, (mem_end - BZIMAGE_LOAD).next_multiple_of(4096)); // init_size
    // kernel_version: the offset of the version string, less 0x200.
    let version = format!("rukernel {}\0", env!("CARGO_PKG_VERSION"));
    let at = BZIMAGE_SETUP_SIZE - 0x200;
    image[at..at + version.len()].copy_from_slice(version.as_bytes());
    put::<2>(&mut image, 0x20e, (at - 0x200) as u64);
    pe_header(&mut image, payload.len() as u64);
    image.extend_from_slice(&payload);
    Ok(image)
}

/// The file alignment of the PE image. It is also the alignment of the payload.
const PE_FILE_ALIGN: usize = 0x200;
/// The offset of the PE signature in the boot sector.
const PE_OFFSET: usize = 0x40;
/// The offset of `rk_efi_entry` from the start of the payload, per `boot.rs`.
const EFI_ENTRY: u64 = 0x400;

/// Writes the PE/COFF header in the boot sector, so that UEFI firmware can start the bzImage as
/// an EFI application, per the PE format of Microsoft. The image has one section. It is the
/// payload, at the first page after the setup part. The image has no relocations, because the
/// EFI stub uses only RIP relative addresses.
fn pe_header(image: &mut [u8], payload: u64) {
    let setup = BZIMAGE_SETUP_SIZE as u64;
    image[0..2].copy_from_slice(b"MZ");
    put::<4>(image, 0x3c, PE_OFFSET as u64); // e_lfanew
    let coff = PE_OFFSET + 4;
    image[PE_OFFSET..coff].copy_from_slice(b"PE\0\0");
    put::<2>(image, coff, 0x8664); // Machine: x86-64
    put::<2>(image, coff + 2, 1); // NumberOfSections
    put::<2>(image, coff + 16, 240); // SizeOfOptionalHeader
    put::<2>(image, coff + 18, 0x0206); // EXECUTABLE_IMAGE, LINE_NUMS_STRIPPED, DEBUG_STRIPPED
    let opt = coff + 20;
    put::<2>(image, opt, 0x20b); // PE32+
    put::<4>(image, opt + 4, payload); // SizeOfCode
    put::<4>(image, opt + 16, setup + EFI_ENTRY); // AddressOfEntryPoint
    put::<4>(image, opt + 20, setup); // BaseOfCode
    put::<4>(image, opt + 32, 0x1000); // SectionAlignment
    put::<4>(image, opt + 36, PE_FILE_ALIGN as u64); // FileAlignment
    put::<4>(image, opt + 56, setup + payload.next_multiple_of(0x1000)); // SizeOfImage
    put::<4>(image, opt + 60, setup); // SizeOfHeaders
    put::<2>(image, opt + 68, 10); // Subsystem: EFI application
    put::<4>(image, opt + 108, 16); // NumberOfRvaAndSizes. Each data directory is empty.
    let section = opt + 240;
    image[section..section + 8].copy_from_slice(b".text\0\0\0");
    put::<4>(image, section + 8, payload); // VirtualSize
    put::<4>(image, section + 12, setup); // VirtualAddress
    put::<4>(image, section + 16, payload); // SizeOfRawData
    put::<4>(image, section + 20, setup); // PointerToRawData
    put::<4>(image, section + 36, 0x6000_0020); // CNT_CODE, MEM_EXECUTE, MEM_READ
}

/// Builds the x86-64 kernel and the bzImage, and gives the path of the bzImage.
fn build_bzimage() -> Result<PathBuf> {
    let kernel = build_kernel()?;
    let elf = fs::read(&kernel).map_err(|e| format!("{}: {e}", kernel.display()))?;
    let path = kernel.with_file_name("bzImage");
    fs::write(&path, bzimage(&elf)?).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(path)
}

/// The QEMU command for the x86-64 kernel. KVM is used when the host has it and this user can open
/// it. A CI runner can have `/dev/kvm` with no access for the runner user.
fn qemu_command(kernel: &Path, cmdline: &str) -> Command {
    let mut cmd = Command::new("qemu-system-x86_64");
    cmd.args(["-machine", "q35", "-m", "512M", "-smp", "1", "-display", "none"])
        .args(["-serial", "stdio", "-no-reboot", "-monitor", "none"])
        .args(["-device", "isa-debug-exit,iobase=0xf4,iosize=0x04"])
        .arg("-kernel")
        .arg(kernel)
        .arg("-initrd")
        .arg(kernel.with_file_name("initramfs.cpio"))
        .args(["-append", cmdline]);
    if fs::OpenOptions::new().read(true).write(true).open("/dev/kvm").is_ok() {
        cmd.args(["-accel", "kvm", "-cpu", "host"]);
    } else {
        cmd.args(["-accel", "tcg", "-cpu", "max"]);
    }
    cmd
}

fn qemu(args: &[String]) -> Result {
    let kernel = build_kernel()?;
    let cmdline = if args.is_empty() { String::from("console=ttyS0") } else { args.join(" ") };
    let status = qemu_command(&kernel, &cmdline)
        .status()
        .map_err(|e| format!("cannot run qemu-system-x86_64: {e}"))?;
    println!("qemu exited with {status}");
    Ok(())
}

/// Tells if the boot test `test` can run. The `init` and `tty` tests need the user programs.
fn can_run(kernel: &Path, test: &str) -> bool {
    !matches!(test, "init" | "tty") || kernel.with_file_name("user-init").exists()
}

/// The command line of a boot test. The `tty` test runs init with the argument `tty`, which is
/// after `--`, as Linux gives the arguments of init.
fn test_cmdline(test: &str) -> String {
    match test {
        "tty" => String::from("console=ttyS0 rk.test=init -- tty"),
        _ => format!("console=ttyS0 rk.test={test}"),
    }
}

/// The line that the kernel prints when the boot test `test` passes.
fn pass_line(test: &str) -> String {
    let test = if test == "tty" { "init" } else { test };
    format!("rk.test={test}: pass")
}

/// The input of a boot test. When the log has the text of an entry, the test writes the bytes of
/// the entry to the serial port. The `tty` test types a line and then `^C`.
fn test_input(test: &str) -> &'static [(&'static str, &'static [u8])] {
    match test {
        "tty" => &[("init: type a line", b"hello\n"), ("init: press ^C", b"\x03")],
        _ => &[],
    }
}

fn boot_test() -> Result {
    let kernel = build_kernel()?;
    let mut errors = Vec::new();
    for test in BOOT_TESTS.iter().filter(|t| can_run(&kernel, t)) {
        let cmd = qemu_command(&kernel, &test_cmdline(test));
        let (status, log) = run_with_timeout(cmd, BOOT_TEST_TIMEOUT, test_input(test))?;
        let passed = status == Some(QEMU_PASS) && log.contains(&pass_line(test));
        if passed {
            println!("boot test {test}: pass");
        } else {
            let status = status.map_or(String::from("a timeout"), |s| format!("status {s}"));
            errors.push(format!("boot test {test}: fail with {status}\n{log}"));
        }
    }
    let bzimage = build_bzimage()?;
    for test in BZIMAGE_TESTS.iter().filter(|t| can_run(&kernel, t)) {
        let cmd = qemu_command(&bzimage, &test_cmdline(test));
        let (status, log) = run_with_timeout(cmd, BOOT_TEST_TIMEOUT, test_input(test))?;
        let passed = status == Some(QEMU_PASS)
            && log.contains("booting with linux")
            && log.contains(&pass_line(test));
        if passed {
            println!("boot test {test} with the bzImage: pass");
        } else {
            let status = status.map_or(String::from("a timeout"), |s| format!("status {s}"));
            errors.push(format!("boot test {test} with the bzImage: fail with {status}\n{log}"));
        }
    }
    match find_ovmf()? {
        Some(firmware) => {
            for test in BZIMAGE_TESTS.iter().filter(|t| can_run(&kernel, t)) {
                let mut cmd = qemu_command(&bzimage, &test_cmdline(test));
                cmd.arg("-drive")
                    .arg(format!("if=pflash,format=raw,readonly=on,file={}", firmware.display()));
                let (status, log) = run_with_timeout(cmd, BOOT_TEST_TIMEOUT, test_input(test))?;
                let passed = status == Some(QEMU_PASS)
                    && log.contains("booting with efi")
                    && log.contains(&pass_line(test));
                if passed {
                    println!("boot test {test} with UEFI: pass");
                } else {
                    let status =
                        status.map_or(String::from("a timeout"), |s| format!("status {s}"));
                    errors.push(format!("boot test {test} with UEFI: fail with {status}\n{log}"));
                }
            }
        }
        None => println!("boot tests with UEFI: skipped, no OVMF firmware, set RK_OVMF"),
    }
    report("boot tests", errors)
}

/// The places where a package puts the OVMF firmware: Homebrew, Debian and Ubuntu, and Fedora.
const OVMF_PATHS: &[&str] = &[
    "/opt/homebrew/share/qemu/edk2-x86_64-code.fd",
    "/usr/local/share/qemu/edk2-x86_64-code.fd",
    "/usr/share/OVMF/OVMF_CODE_4M.fd",
    "/usr/share/OVMF/OVMF_CODE.fd",
    "/usr/share/edk2/ovmf/OVMF_CODE.fd",
    "/usr/share/qemu/edk2-x86_64-code.fd",
];

/// Finds the OVMF firmware for the UEFI boot tests. `RK_OVMF` gives the path. In CI the firmware
/// must be there, so that CI does not skip the tests.
fn find_ovmf() -> Result<Option<PathBuf>> {
    if let Some(path) = std::env::var_os("RK_OVMF") {
        return Ok(Some(PathBuf::from(path)));
    }
    let found = OVMF_PATHS.iter().map(PathBuf::from).find(|p| p.exists());
    if found.is_none() && std::env::var_os("CI").is_some() {
        return Err(String::from("no OVMF firmware for the UEFI boot tests, install ovmf"));
    }
    Ok(found)
}

/// Runs a command, collects its standard output and stops it after `timeout`. When the output has
/// the text of the next entry of `input`, the bytes of the entry go to the standard input of the
/// command. Gives the exit status, or `None` for a timeout.
fn run_with_timeout(
    mut cmd: Command,
    timeout: Duration,
    input: &[(&str, &[u8])],
) -> Result<(Option<i32>, String)> {
    let mut child = cmd
        .stdout(Stdio::piped())
        .stdin(if input.is_empty() { Stdio::null() } else { Stdio::piped() })
        .spawn()
        .map_err(|e| format!("cannot run {:?}: {e}", cmd.get_program()))?;
    let mut stdout = child.stdout.take().ok_or("no standard output")?;
    let mut stdin = child.stdin.take();
    let out = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let reader = {
        let out = out.clone();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok(n) = stdout.read(&mut buf) {
                if n == 0 {
                    break;
                }
                out.lock().unwrap_or_else(|e| e.into_inner()).extend_from_slice(&buf[..n]);
            }
        })
    };
    let mut next = input.iter();
    let mut waiting = next.next();
    let start = Instant::now();
    let status = loop {
        if let (Some((text, bytes)), Some(pipe)) = (waiting, stdin.as_mut()) {
            let seen = {
                let out = out.lock().unwrap_or_else(|e| e.into_inner());
                String::from_utf8_lossy(&out).contains(text)
            };
            if seen {
                pipe.write_all(bytes).and_then(|()| pipe.flush()).map_err(|e| e.to_string())?;
                waiting = next.next();
            }
        }
        if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
            break status.code();
        }
        if start.elapsed() > timeout {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    drop(stdin);
    let _ = reader.join();
    let log = String::from_utf8_lossy(&out.lock().unwrap_or_else(|e| e.into_inner())).into_owned();
    Ok((status, log))
}

fn cargo(args: &[&str]) -> Result {
    println!("cargo {}", args.join(" "));
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| String::from("cargo"));
    let status = Command::new(cargo)
        .args(args)
        .current_dir(workspace_root())
        .status()
        .map_err(|e| format!("cannot run cargo: {e}"))?;
    if status.success() { Ok(()) } else { Err(format!("cargo {} failed", args.join(" "))) }
}

fn report(check: &str, errors: Vec<String>) -> Result {
    if errors.is_empty() {
        println!("{check}: ok");
        Ok(())
    } else {
        Err(format!("{check}: {} problems\n{}", errors.len(), errors.join("\n")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_forbid_attribute() {
        assert!(forbids_unsafe("//! A crate.\n\n#![forbid(unsafe_code)]\n"));
        assert!(!forbids_unsafe("//! A crate.\n#![deny(unsafe_code)]\n"));
        assert!(!forbids_unsafe("// #![forbid(unsafe_code)] is not here\n"));
    }

    #[test]
    fn code_count() {
        let mut count = CodeCount::default();
        count.add(
            "//! A module.\n\n\
             fn f() {\n\
             \x20   // SAFETY: a reason.\n\
             \x20   unsafe { g() };\n\
             \x20   let x = unsafe { h() } + unsafe { h() }; // unsafe { not this }\n\
             }\n\
             unsafe impl Sync for T {}\n",
        );
        assert_eq!(count, CodeCount { lines: 5, unsafe_blocks: 3 });
    }

    #[test]
    fn horizontal_rules() {
        assert!(is_horizontal_rule("---"));
        assert!(is_horizontal_rule("* * *"));
        assert!(!is_horizontal_rule("|---|---|"));
        assert!(!is_horizontal_rule("--"));
    }

    #[test]
    fn dependency_tables() {
        let names: BTreeSet<&str> = ["rk-abi", "rk-lib"].into_iter().collect();
        let manifest = "[package]\nname = \"x\"\n\n[dependencies]\nrk-abi.workspace = true\nrk-lib = { workspace = true }\nother = \"1\"\n\n[lints]\nrk-lib = 1\n";
        assert_eq!(dependencies(manifest, &names), ["rk-abi", "rk-lib"]);
    }
}
