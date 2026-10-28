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
        "boot-test" => boot_test(&std::env::args().skip(2).collect::<Vec<_>>()),
        "abi" => check_abi(),
        "ci" => ci(),
        _ => Err(String::from(
            "usage: cargo xtask <unsafe | layers | style | targets | qemu | boot-test | ci>\n\n\
             unsafe   each crate root forbids unsafe code, except the crates in xtask/unsafe-allowed.txt\n\
             layers   each crate depends only on its layer or a lower layer, per xtask/layers.txt\n\
             style    the prose has no em dashes, no en dashes and no horizontal rules\n\
             targets  the kernel crates build for the three bare metal targets\n\
             qemu     boot the x86-64 kernel in QEMU, with the arguments as the command line\n\
             boot-test  boot the kernel in QEMU and check the self tests, or only the named tests;\n\
                        `aarch64` names the arm64 tests on QEMU virt\n\
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
    boot_test(&[])?;
    cargo(&["doc", "--workspace", "--no-deps"])?;
    println!("all checks passed");
    Ok(())
}

/// The QEMU exit status for a passed self test: `(0x10 << 1) | 1`, per kernel/rukernel/src/kernel.rs.
const QEMU_PASS: i32 = 33;

/// The longest time that one boot test can take. TCG on a slow CI runner is the slowest case.
const BOOT_TEST_TIMEOUT: Duration = Duration::from_secs(120);

/// The longest time that a boot test of the init program can take, for example `init` and `smp`.
/// Init runs about 650 checks. On a busy host, QEMU gets only part of a CPU, and the `init` test
/// can take more than `BOOT_TEST_TIMEOUT` (#396).
const INIT_TEST_TIMEOUT: Duration = Duration::from_secs(300);

/// The longest time that the `smp` boot test can take. It runs the init checks on `SMP_CPUS` CPUs,
/// and on a busy host it can take more than 300 s, because all kernel code runs under one lock.
const SMP_TEST_TIMEOUT: Duration = Duration::from_secs(600);

/// The longest time that a boot test of a root file system can take. The `alpine` test makes and
/// checks file systems on two disks, and it is slow on a busy host.
const ROOTFS_TIMEOUT: Duration = Duration::from_secs(300);

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
    "smp",
    "blk",
    "net",
    "inet",
    "netcfg",
    "inet6",
    "netns",
    "busybox",
    "ltp",
    "kselftest",
    "gvisor",
    "alpine",
    "debian",
    "fstests",
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

/// Finds a C compiler that makes arm64 Linux programs with musl, for the arm64 user tests. `RK_USER_CC_AARCH64` gives the command, for example `aarch64-linux-musl-gcc`, `zig cc
/// -target aarch64-linux-musl`, or a script that runs the gcc of Alpine for arm64 in a container.
/// Then `aarch64-linux-musl-gcc` and `zig` are tried. Without a compiler, the tests are skipped.
fn find_user_cc_aarch64() -> Option<UserCc> {
    let works = |cmd: &str, arg: &str| {
        Command::new(cmd).arg(arg).stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok()
    };
    let make = |command: Vec<String>| {
        let is_zig = command.first().is_some_and(|c| c.ends_with("zig"));
        UserCc {
            command,
            static_flags: &["-static"],
            pie_flags: if is_zig { &["-static", "-fPIE"] } else { &["-static-pie", "-fPIE"] },
        }
    };
    if let Ok(cc) = std::env::var("RK_USER_CC_AARCH64") {
        return Some(make(cc.split_whitespace().map(String::from).collect()));
    }
    if works("aarch64-linux-musl-gcc", "--version") {
        return Some(make(vec![String::from("aarch64-linux-musl-gcc")]));
    }
    if works("zig", "version") {
        return Some(make(
            ["zig", "cc", "-target", "aarch64-linux-musl"].map(String::from).to_vec(),
        ));
    }
    None
}

/// Compiles the user test program `name` from tests/user to `out`.
fn compile_user(cc: &UserCc, name: &str, pie: bool, out: &Path) -> Result {
    compile_c(&cc.command, if pie { cc.pie_flags } else { cc.static_flags }, name, out)
}

/// Compiles the program `name` from tests/user to `out` with the compiler `command` and `flags`.
fn compile_c(command: &[String], flags: &[&str], name: &str, out: &Path) -> Result {
    let src = workspace_root().join("tests/user").join(format!("{name}.c"));
    let status = Command::new(&command[0])
        .args(&command[1..])
        .args(flags)
        .args(["-O2", "-s", "-Wall", "-Werror", "-o"])
        .arg(out)
        .arg(&src)
        .status()
        .map_err(|e| format!("{}: {e}", command[0]))?;
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

/// Finds a C compiler that makes dynamic x86-64 Linux programs with glibc. `RK_GLIBC_CC` gives
/// the command. On an x86-64 Linux host, `cc` is used. Then `zig cc -target x86_64-linux-gnu` is
/// tried. CI must have a compiler, so that CI does not skip the `debian` test.
fn find_glibc_cc() -> Result<Option<Vec<String>>> {
    if let Ok(cc) = std::env::var("RK_GLIBC_CC") {
        return Ok(Some(cc.split_whitespace().map(String::from).collect()));
    }
    let works = |cmd: &str, arg: &str| {
        Command::new(cmd).arg(arg).stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok()
    };
    if cfg!(all(target_os = "linux", target_arch = "x86_64")) && works("cc", "--version") {
        return Ok(Some(vec![String::from("cc")]));
    }
    if works("zig", "version") {
        return Ok(Some(["zig", "cc", "-target", "x86_64-linux-gnu"].map(String::from).to_vec()));
    }
    if std::env::var_os("CI").is_some() {
        return Err(String::from("no C compiler for glibc programs, set RK_GLIBC_CC"));
    }
    Ok(None)
}

/// The static BusyBox that the `busybox` boot test runs, from the binaries of busybox.net. The
/// test checks the SHA-256 of the file. `RK_BUSYBOX` gives the path of a different BusyBox.
const BUSYBOX_URL: &str = "https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox";
const BUSYBOX_SHA256: &str = "6e123e7f3202a8c1e9b1f94d8941580a25135382b99e8d3e34fb858bba311348";

/// The applets that the `busybox` and `kselftest` boot tests use. Each one is a link to
/// /bin/busybox.
const BUSYBOX_APPLETS: &[&str] = &[
    "sh", "echo", "tr", "sleep", "cat", "wc", "ls", "test", "mkdir", "rm", "true", "false",
    "mount", "grep", "sed", "ip", "ifconfig", "route", "ping",
];

/// Gives the SHA-256 of `path` in hexadecimal, from `sha256sum` or `shasum`.
fn sha256(path: &Path) -> Result<String> {
    for cmd in [&["sha256sum"][..], &["shasum", "-a", "256"]] {
        let Ok(out) = Command::new(cmd[0]).args(&cmd[1..]).arg(path).output() else {
            continue;
        };
        if out.status.success() {
            let text = String::from_utf8_lossy(&out.stdout);
            return Ok(text.split_whitespace().next().unwrap_or_default().to_owned());
        }
    }
    Err(String::from("no sha256sum or shasum for the check of BusyBox"))
}

/// Downloads `url` with `curl` to `path` if the file is not there, and checks its SHA-256. Gives
/// `false` if the download failed and the run is not in CI. `name` is the name in the messages,
/// and `var` is the variable that gives a different file.
fn download(url: &str, sha: &str, path: &Path, name: &str, var: &str) -> Result<bool> {
    if !path.exists() {
        let status = Command::new("curl")
            .args(["--silent", "--show-error", "--fail", "--location", "--output"])
            .arg(path)
            .arg(url)
            .status();
        if !status.is_ok_and(|s| s.success()) {
            let _ = fs::remove_file(path);
            if std::env::var_os("CI").is_some() {
                return Err(format!("cannot download {url}"));
            }
            println!("{name}: skipped, the download failed, set {var}");
            return Ok(false);
        }
    }
    let sum = sha256(path)?;
    if sum != sha {
        let _ = fs::remove_file(path);
        return Err(format!("{}: the SHA-256 is {sum}, not {sha}", path.display()));
    }
    Ok(true)
}

/// Gives the bytes of the static BusyBox. The first run downloads it with `curl` into the
/// directory `dir`. Gives `None` if there is no BusyBox and the run is not in CI.
fn busybox(dir: &Path) -> Result<Option<Vec<u8>>> {
    let read = |p: &Path| fs::read(p).map_err(|e| format!("{}: {e}", p.display()));
    if let Some(path) = std::env::var_os("RK_BUSYBOX") {
        return read(Path::new(&path)).map(Some);
    }
    let path = dir.join("busybox");
    if !download(BUSYBOX_URL, BUSYBOX_SHA256, &path, "busybox", "RK_BUSYBOX")? {
        return Ok(None);
    }
    read(&path).map(Some)
}

/// A root file system that a boot test downloads and runs. Its programs use a dynamic loader. The
/// test checks the SHA-256 of the file, and the variable `var` gives the path of a different file.
struct Rootfs {
    /// The name of the boot test.
    name: &'static str,
    url: &'static str,
    sha256: &'static str,
    var: &'static str,
    /// The script that runs as /init. `set -e` stops it at the first command that fails.
    init: &'static str,
    /// The programs from tests/user that the test compiles with glibc and puts in
    /// /usr/local/bin with the prefix `rk-`.
    glibc_programs: &'static [&'static str],
    /// The test adds the tree of tools/debug/build.sh, if it is there.
    debug_tools: bool,
}

/// The root file systems of the boot tests. The Alpine programs use musl, and the Debian programs
/// use glibc.
const ROOTFS: &[Rootfs] = &[
    Rootfs {
        name: "alpine",
        url: "https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/x86_64/alpine-minirootfs-3.24.3-x86_64.tar.gz",
        sha256: "f8e1cafba9b1b283b5d30d06f9885c8d2bc161ffe9083ade8e2e157813a53407",
        var: "RK_ALPINE",
        init: "#!/bin/sh
set -e
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t tmpfs dev /dev
busybox mdev -s
test -c /dev/null && test -c /dev/ttyS0
ls -l /dev/null | grep -q ' 1, *3 '
echo \"alpine: mdev made $(ls /dev | wc -l) device files\"
echo \"alpine: release $(cat /etc/alpine-release)\"
ls -l /lib/ld-musl-x86_64.so.1
/lib/ld-musl-x86_64.so.1 --list /bin/busybox
apk --version
apk info --no-network | grep -q musl
echo one two | tr a-z A-Z | grep -q 'ONE TWO'
sleep 100 &
pid=$!
until grep -qx sleep /proc/$pid/comm; do :; done
busybox ps -o pid,ppid,user,stat,rss,args | grep -q \"^ *$pid *1 *root *S *[1-9][0-9]* *sleep 100$\"
busybox pgrep -x sleep | grep -qx $pid
busybox top -b -n 1 | grep -q \"^ *$pid *1 *root *S .* sleep 100$\"
kill $pid
if [ -x /usr/bin/gdb ]; then
    export PATH=/usr/sbin:/usr/bin:/sbin:/bin
    strace -f -o /tmp/strace.log sh -c 'echo one | tr a-z A-Z' | grep -qx ONE
    grep -q '^[0-9]* *execve(\"/usr/bin/tr\"' /tmp/strace.log
    grep -q '^[0-9]* *pipe(\\[3, 4\\]) *= 0' /tmp/strace.log
    grep -q '+++ exited with 0 +++' /tmp/strace.log
    echo \"alpine: strace traced $(grep -c . /tmp/strace.log) lines\"
    gdb -batch -nx -ex 'break square' -ex run -ex 'print n' -ex next -ex next -ex delete -ex continue \\
        /usr/local/bin/rk-count > /tmp/gdb.log 2>&1
    grep -q 'Breakpoint 1, square (n=1)' /tmp/gdb.log
    grep -q '^\\$1 = 1$' /tmp/gdb.log
    grep -q 'count: 14' /tmp/gdb.log
    grep -q 'exited normally' /tmp/gdb.log || { cat /tmp/gdb.log; exit 1; }
    echo 'alpine: gdb done'
    sleep 100 &
    pid=$!
    until grep -qx sleep /proc/$pid/comm; do :; done
    ps -o pid=,ppid=,user=,stat=,comm=,args= -p $pid | grep -q \"^ *$pid *1 root *S *sleep *sleep 100$\"
    test \"$(ps -o rss= -p $pid)\" -gt 0
    pgrep -x sleep | grep -qx $pid
    pidof sleep | grep -qx $pid
    top -b -n 1 > /tmp/top.log
    grep -q '^Tasks: *[0-9]* total' /tmp/top.log
    awk -v p=$pid '$1 == p && $2 == \"root\" && $6 > 0 && $8 == \"S\" && $12 == \"sleep\"' /tmp/top.log | grep -q .
    kill $pid
    echo 'alpine: ps, top and pgrep done'
    fio --name=rk --filename=/dev/vda --ioengine=libaio --direct=1 --iodepth=8 --bs=4k \\
        --rw=randwrite --size=1M --verify=crc32c --thread --output=/tmp/fio.log
    grep -q 'rk: (groupid=0, jobs=1): err= 0' /tmp/fio.log || { cat /tmp/fio.log; exit 1; }
    echo 'alpine: fio done'
    udevadm info --query=all --name=/dev/vda > /tmp/udev.log 2>&1 || { cat /tmp/udev.log; exit 1; }
    grep -q '^P: /devices/virtual/block/vda$' /tmp/udev.log
    grep -q '^E: DEVNAME=/dev/vda$' /tmp/udev.log
    grep -q '^E: DEVTYPE=disk$' /tmp/udev.log
    grep -q '^E: SUBSYSTEM=block$' /tmp/udev.log
    echo 'alpine: udevadm done'
    mkdir -p /tmp/tree/a/b/c /tmp/tree/many /mnt
    cp -a /etc /tmp/tree/etc
    head -c 3000000 /dev/urandom > /tmp/tree/a/big
    printf 'small\\n' > /tmp/tree/a/b/c/small
    ln -s ../big /tmp/tree/a/b/link
    ln -s $(printf 'x%.0s' $(seq 100)) /tmp/tree/long
    for i in $(seq 400); do echo $i > /tmp/tree/many/file-$i; done
    mkfs.ext4 -q -d /tmp/tree /dev/vdb
    mount -t ext4 -o ro /dev/vdb /mnt
    test -d /mnt/lost+found
    mkdir /tmp/tree/lost+found
    diff -r --no-dereference /tmp/tree /mnt
    cmp /tmp/tree/a/big /mnt/a/b/link
    test \"$(stat -c '%s %h' /mnt/a/big)\" = '3000000 1'
    test \"$(readlink /mnt/long)\" = \"$(readlink /tmp/tree/long)\"
    ! touch /mnt/new 2>/dev/null
    echo \"alpine: ext4 read $(find /mnt | wc -l) files\"
    umount /mnt
    mount -t ext4 /dev/vdb /mnt
    echo one > /mnt/new
    echo two >> /mnt/new
    test \"$(cat /mnt/new)\" = \"$(printf 'one\\ntwo')\"
    head -c 200000 /dev/urandom > /tmp/r
    cp /tmp/r /mnt/r
    cmp /tmp/r /mnt/r
    truncate -s 1000 /mnt/r
    mkdir -p /mnt/d/e
    mv /mnt/new /mnt/d/e/new
    ln /mnt/d/e/new /mnt/hard
    ln -s d/e/new /mnt/soft
    for i in $(seq 300); do echo $i > /mnt/d/f$i; done
    rm -r /mnt/many /mnt/etc
    rm /mnt/d/f7
    ! rmdir /mnt/d 2>/dev/null
    dumpe2fs -h /dev/vdb 2>/dev/null | grep -q needs_recovery
    dd if=/dev/vdb of=/tmp/crash.img bs=64k 2>/dev/null
    e2fsck -fy /tmp/crash.img > /tmp/crash.log 2>&1 || true
    ! grep -q '? yes' /tmp/crash.log || { cat /tmp/crash.log; exit 1; }
    e2fsck -fn /tmp/crash.img
    rm /tmp/crash.img
    umount /mnt
    ! dumpe2fs -h /dev/vdb 2>/dev/null | grep -q needs_recovery
    e2fsck -fn /dev/vdb
    mount -t ext4 -o ro /dev/vdb /mnt
    test \"$(cat /mnt/soft)\" = \"$(printf 'one\\ntwo')\"
    test \"$(stat -c '%h' /mnt/hard)\" = 2
    head -c 1000 /tmp/r | cmp - /mnt/r
    test ! -e /mnt/many -a ! -e /mnt/d/f7 -a -e /mnt/d/f300
    umount /mnt
    echo 'alpine: ext4 write done'
    bs=$(dumpe2fs -h /dev/vdb 2>/dev/null | sed -n 's/^Block size: *//p')
    blk=$(debugfs -R 'bmap /d/f300 0' /dev/vdb 2>/dev/null)
    { printf 'abc\\n'; head -c $((bs - 4)) /dev/zero; } > /tmp/jblk
    printf 'jo\\njw -b %s /tmp/jblk\\njc\\n' $blk > /tmp/j.cmd
    debugfs -w -f /tmp/j.cmd /dev/vdb >/dev/null 2>&1
    dumpe2fs -h /dev/vdb 2>/dev/null | grep -q needs_recovery
    mount -t ext4 -o ro /dev/vdb /mnt
    test \"$(cat /mnt/d/f300)\" = abc
    umount /mnt
    ! dumpe2fs -h /dev/vdb 2>/dev/null | grep -q needs_recovery
    e2fsck -fn /dev/vdb
    echo 'alpine: ext4 journal replay done'
    mount -t ext4 /dev/vdb /mnt
    mkdir -p /tmp/m2
    mount -t ext4 /dev/vdb /tmp/m2
    echo same > /mnt/same
    test \"$(cat /tmp/m2/same)\" = same
    ! mount -t ext4 -o ro /dev/vdb /tmp/m2 2>/dev/null
    rm /tmp/m2/same
    test ! -e /mnt/same
    umount /tmp/m2
    python3 -c 'import os
p = \"/mnt/d/e/new\"
os.setxattr(p, \"user.small\", b\"1\")
os.setxattr(p, \"user.large\", b\"x\" * 700)
os.setxattr(\"/mnt/d\", \"trusted.overlay.opaque\", b\"y\")
os.setxattr(\"/mnt/r\", \"user.gone\", b\"z\" * 700)
os.removexattr(\"/mnt/r\", \"user.gone\")'
    umount /mnt
    e2fsck -fn /dev/vdb
    debugfs -R 'ea_list /d/e/new' /dev/vdb 2>/dev/null > /tmp/ea
    grep -q 'user.small (1) = \"1\"' /tmp/ea || { cat /tmp/ea; exit 1; }
    grep -q 'user.large (700)' /tmp/ea || { cat /tmp/ea; exit 1; }
    debugfs -R 'ea_list /d' /dev/vdb 2>/dev/null | grep -q 'trusted.overlay.opaque (1) = \"y\"'
    ! debugfs -R 'ea_list /r' /dev/vdb 2>/dev/null | grep -q user.gone
    mount -t ext4 -o ro /dev/vdb /mnt
    python3 -c 'import os; assert os.getxattr(\"/mnt/d/e/new\", \"user.large\") == b\"x\" * 700'
    umount /mnt
    echo 'alpine: ext4 xattr done'
    mkfs.xfs -q -K -p file=/tmp/tree /dev/vdc
    mount -t xfs -o ro /dev/vdc /mnt
    diff -r --no-dereference /tmp/tree /mnt
    cmp /tmp/tree/a/big /mnt/a/b/link
    test \"$(stat -c '%s %h %a' /mnt/a/big)\" = \"$(stat -c '%s %h %a' /tmp/tree/a/big)\"
    test \"$(readlink /mnt/long)\" = \"$(readlink /tmp/tree/long)\"
    test \"$(ls /mnt/many | wc -l)\" = 400
    test \"$(stat -f -c %T /mnt)\" = xfs
    ! touch /mnt/new 2>/dev/null
    echo \"alpine: xfs read $(find /mnt | wc -l) files\"
    umount /mnt
fi
echo 'alpine: done'
",
        glibc_programs: &[],
        debug_tools: true,
    },
    Rootfs {
        name: "debian",
        url: "https://raw.githubusercontent.com/debuerreotype/docker-debian-artifacts/cee78df586385250331cacba8fd1140133c054e5/trixie/slim/oci/blobs/rootfs.tar.gz",
        sha256: "f2be67225471500c788ce88c597eb5ea8336e912ad1ca4815650e0281afe2034",
        var: "RK_DEBIAN",
        init: "#!/bin/sh
set -e
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
mount -t proc proc /proc
echo \"debian: version $(cat /etc/debian_version)\"
/lib64/ld-linux-x86-64.so.2 --list /usr/bin/bash
bash -c 'echo \"debian: bash $BASH_VERSION\"'
ls -l /usr/lib/x86_64-linux-gnu/libc.so.6
echo one two | tr a-z A-Z | grep -q 'ONE TWO'
printf 'b\\na\\n' | sort | head -n 1 | grep -qx a
dpkg-query -W libc6
apt-get --version | head -n 1
perl -e 'print \"debian: perl $]\\n\"'
find /etc -name debian_version | grep -q debian_version
/usr/local/bin/rk-nptl
echo 'debian: done'
",
        glibc_programs: &["nptl"],
        debug_tools: false,
    },
];

/// Adds each file under `root` to `w`, with its mode, as a path relative to `root`. A directory
/// comes before its contents.
fn add_tree(w: &mut rk_vfs::cpio::Writer, root: &Path, dir: &Path) -> Result {
    use std::os::unix::fs::PermissionsExt;
    let mut entries: Vec<_> = fs::read_dir(dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?
        .filter_map(std::result::Result::ok)
        .map(|e| e.path())
        .collect();
    entries.sort();
    for path in entries {
        let meta = fs::symlink_metadata(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let rel = path.strip_prefix(root).map_err(|e| e.to_string())?;
        let name = rel.to_string_lossy();
        let mode = meta.permissions().mode() & 0o7777;
        if meta.file_type().is_symlink() {
            let target = fs::read_link(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            w.add(name.as_bytes(), 0o120_000 | mode, target.to_string_lossy().as_bytes());
        } else if meta.is_dir() {
            w.add(name.as_bytes(), 0o040_000 | mode, b"");
            add_tree(w, root, &path)?;
        } else if meta.is_file() {
            let bytes = fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            w.add(name.as_bytes(), 0o100_000 | mode, &bytes);
        }
    }
    Ok(())
}

/// Writes the initramfs of the boot test of `rootfs` next to the kernel: the root file system and
/// the script of `rootfs.init` as /init. Gives `false` if there is no file for the root file
/// system, or no compiler for its programs.
fn build_rootfs_initramfs(kernel: &Path, rootfs: &Rootfs) -> Result<bool> {
    let dir = kernel.parent().ok_or("the kernel path has no directory")?;
    let glibc_cc = if rootfs.glibc_programs.is_empty() { None } else { find_glibc_cc()? };
    if !rootfs.glibc_programs.is_empty() && glibc_cc.is_none() {
        println!("{}: skipped, no C compiler for glibc, set RK_GLIBC_CC", rootfs.name);
        return Ok(false);
    }
    let tarball = match std::env::var_os(rootfs.var) {
        Some(path) => PathBuf::from(path),
        None => {
            let path = dir.join(format!("{}-rootfs.tar.gz", rootfs.name));
            if !download(rootfs.url, rootfs.sha256, &path, rootfs.name, rootfs.var)? {
                return Ok(false);
            }
            path
        }
    };
    let root = dir.join(format!("{}-root", rootfs.name));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).map_err(|e| format!("{}: {e}", root.display()))?;
    let status = Command::new("tar")
        .arg("-xzf")
        .arg(&tarball)
        .arg("-C")
        .arg(&root)
        .status()
        .map_err(|e| format!("cannot run tar: {e}"))?;
    if !status.success() {
        return Err(format!("tar cannot unpack {}", tarball.display()));
    }
    if let Some(cc) = glibc_cc {
        let bin = root.join("usr/local/bin");
        fs::create_dir_all(&bin).map_err(|e| format!("{}: {e}", bin.display()))?;
        for name in rootfs.glibc_programs {
            compile_c(&cc, &["-pthread"], name, &bin.join(format!("rk-{name}")))?;
        }
    }
    if let Some(tools) = debug_tools_dir().filter(|_| rootfs.debug_tools) {
        // `cp -R` keeps the symbolic links of the tree. With `-f`, a file of the tree replaces a link to
        // BusyBox, which points to a path outside the tree.
        let status = Command::new("cp")
            .arg("-pRf")
            .arg(tools.join("root/."))
            .arg(&root)
            .status()
            .map_err(|e| format!("cannot run cp: {e}"))?;
        if !status.success() {
            return Err(format!("cp cannot copy {}", tools.display()));
        }
    }
    let mut w = rk_vfs::cpio::Writer::new();
    w.add(b".", 0o040_755, b"");
    add_tree(&mut w, &root, &root)?;
    w.add(b"init", 0o100_755, rootfs.init.as_bytes());
    let path = rootfs_initramfs(kernel, rootfs.name);
    fs::write(&path, w.finish()).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(true)
}

/// The path of the initramfs of the root file system boot test `name`.
fn rootfs_initramfs(kernel: &Path, name: &str) -> PathBuf {
    kernel.with_file_name(format!("initramfs-{name}.cpio"))
}

/// The directory of gdb, strace and their test program that tools/debug/build.sh makes:
/// `RK_DEBUG_TOOLS`, or target/debug-tools.
fn debug_tools_dir() -> Option<PathBuf> {
    let dir = std::env::var_os("RK_DEBUG_TOOLS")
        .map_or_else(|| workspace_root().join("target/debug-tools"), PathBuf::from);
    dir.join("VERSION").exists().then_some(dir)
}

/// The size of the disk of the `ltp` boot test. The tests that need a device, as the tests of the
/// new mount API, get it in `LTP_DEV`. LTP asks for 300 MiB.
const LTP_DISK_SIZE: u64 = 512 << 20;

/// The longest time that the `ltp` boot test can take. It runs each test of tools/ltp/tests.txt.
const LTP_TIMEOUT: Duration = Duration::from_secs(1200);

/// The directory of the LTP tests that tools/ltp/build.sh makes: `RK_LTP`, or target/ltp.
fn ltp_dir() -> Option<PathBuf> {
    let dir = std::env::var_os("RK_LTP")
        .map_or_else(|| workspace_root().join("target/ltp"), PathBuf::from);
    dir.join("VERSION").exists().then_some(dir)
}

/// The names of the LTP tests that the `ltp` boot test runs, from tools/ltp/tests.txt. A line
/// that starts with `#` is a comment.
fn ltp_tests() -> Result<Vec<String>> {
    // RK_LTP_TESTS gives other tests for a run by hand.
    if let Ok(list) = std::env::var("RK_LTP_TESTS") {
        return Ok(list.split_ascii_whitespace().map(String::from).collect());
    }
    let text = read(&workspace_root().join("tools/ltp/tests.txt"))?;
    Ok(text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(String::from)
        .collect())
}

/// The script that the `ltp` boot test runs as init. A test passes with the exit code 0, or 32
/// (`TCONF`) when the test does not apply. The output of a test that fails goes to the console.
/// `LTP_TIMEOUT_MUL` makes the timeouts of the tests 4 times longer, because QEMU without KVM is
/// slow. For example, `futex_cmp_requeue01` forks 1000 waiters, and each waiter stops after 5
/// seconds.
fn ltp_script(tests: &[String]) -> String {
    let mut script = String::from(concat!(
        "#!/bin/sh\nexport TMPDIR=/tmp PATH=/bin:/ltp LTP_TIMEOUT_MUL=4 KCONFIG_PATH=/etc/kconfig\n",
        "export LTP_DEV=/dev/vda\n",
        "mount -t proc proc /proc\nmkdir -p /dev/shm\nmount -t tmpfs shm /dev/shm\n",
        "failed=0\nfor t in \\\n",
    ));
    for t in tests {
        script.push_str(&format!("    {t} \\\n"));
    }
    script.push_str(concat!(
        "; do\n",
        "    /ltp/$t > /tmp/ltp.log 2>&1\n",
        "    code=$?\n",
        "    case $code in\n",
        "    0) echo \"ltp: $t: pass\" ;;\n",
        "    32) echo \"ltp: $t: does not apply\" ;;\n",
        "    *) echo \"ltp: $t: FAIL with $code\"; cat /tmp/ltp.log; failed=1 ;;\n",
        "    esac\n",
        "done\n",
        "exit $failed\n",
    ));
    script
}

/// The longest time that the `kselftest` boot test can take.
const KSELFTEST_TIMEOUT: Duration = Duration::from_secs(900);

/// The directory of the kselftest programs that tools/kselftest/build.sh makes: `RK_KSELFTEST`,
/// or target/kselftest.
fn kselftest_dir() -> Option<PathBuf> {
    let dir = std::env::var_os("RK_KSELFTEST")
        .map_or_else(|| workspace_root().join("target/kselftest"), PathBuf::from);
    dir.join("VERSION").exists().then_some(dir)
}

/// The script that the `kselftest` boot test runs as init. It runs each program in /kselftest. A
/// program passes with the exit code 0, or 4 (`KSFT_SKIP`) when it does not apply. The console
/// gets the totals of each program, and all the output of a program that fails.
const KSELFTEST_SCRIPT: &str = concat!(
    "#!/bin/sh\nexport TMPDIR=/tmp PATH=/bin\n",
    "mount -t proc proc /proc\nmkdir -p /dev/shm\nmount -t tmpfs shm /dev/shm\n",
    "failed=0\nfor p in /kselftest/*; do\n",
    "    t=${p##*/}\n",
    "    [ \"$t\" = run ] && continue\n",
    // The `attached` variant of the URETPROBE tests of seccomp_bpf needs the uprobes of perf,
    // which rukernel does not have.
    "    args=\n    [ \"$t\" = seccomp_bpf ] && args='-V attached'\n",
    "    $p $args > /tmp/kselftest.log 2>&1\n",
    "    code=$?\n",
    "    grep -E '^# (Totals|PASSED|FAILED)' /tmp/kselftest.log | sed \"s/^#/kselftest: $t:/\"\n",
    "    case $code in\n",
    "    0) echo \"kselftest: $t: pass\" ;;\n",
    "    4) echo \"kselftest: $t: does not apply\" ;;\n",
    "    *) echo \"kselftest: $t: FAIL with $code\"; cat /tmp/kselftest.log; failed=1 ;;\n",
    "    esac\n",
    "done\n",
    "exit $failed\n",
);

/// The longest time that the `gvisor` boot test can take.
const GVISOR_TIMEOUT: Duration = Duration::from_secs(1800);

/// The directory of the gVisor tests that tools/gvisor/build.sh makes: `RK_GVISOR`, or
/// target/gvisor.
fn gvisor_dir() -> Option<PathBuf> {
    let dir = std::env::var_os("RK_GVISOR")
        .map_or_else(|| workspace_root().join("target/gvisor"), PathBuf::from);
    dir.join("VERSION").exists().then_some(dir)
}

/// The script that the `gvisor` boot test runs as init. It runs each gtest program in /gvisor. A
/// program passes with the exit code 0. The console gets the totals of each program, and the
/// failed cases and all the output of a program that fails.
const GVISOR_SCRIPT: &str = concat!(
    "#!/bin/sh\nexport TMPDIR=/tmp TEST_TMPDIR=/tmp PATH=/bin\n",
    "mount -t proc proc /proc\nmkdir -p /dev/shm\nmount -t tmpfs shm /dev/shm\n",
    "failed=0\nfor p in /gvisor/*_test; do\n",
    "    t=${p##*/}\n",
    // These tests need user namespaces, network namespaces or capabilities, which come in R5.
    "    $p --gtest_filter=-*SetSocketRecvBufForceAboveMax*:*BindConnectInSubNamespace*:*CredPassDifferentPIDUnprivileged*:*PeerCredAcrossPIDNamespace* > /tmp/gvisor.log 2>&1\n",
    "    code=$?\n",
    "    grep -E '^\\[  (PASSED  |SKIPPED )\\] [0-9]' /tmp/gvisor.log | sed \"s/^/gvisor: $t: /\"\n",
    "    if [ $code = 0 ]; then\n",
    "        echo \"gvisor: $t: pass\"\n",
    "    else\n",
    "        echo \"gvisor: $t: FAIL with $code\"; cat /tmp/gvisor.log; failed=1\n",
    "    fi\n",
    "done\n",
    "exit $failed\n",
);

/// The longest time that the `fstests` boot test can take.
const FSTESTS_TIMEOUT: Duration = Duration::from_secs(3600);
/// The memory of the virtual machine of the `fstests` boot test. The root file system of
/// tools/fstests/build.sh is near 300 MiB, and the initramfs and the tmpfs each keep a copy.
const FSTESTS_MEMORY: &str = "3G";
/// The size of the test disk and of the scratch disk of the `fstests` boot test.
const FSTESTS_DISK_SIZE: u64 = 2 << 30;

/// The directory of the root file system that tools/fstests/build.sh makes: `RK_FSTESTS`, or
/// target/fstests.
fn fstests_dir() -> Option<PathBuf> {
    let dir = std::env::var_os("RK_FSTESTS")
        .map_or_else(|| workspace_root().join("target/fstests"), PathBuf::from);
    (dir.join("VERSION").exists() && dir.join("rootfs.tar.gz").exists()).then_some(dir)
}

/// The arguments of `check` in the `fstests` boot test: the tests of tools/fstests/tests.txt. A
/// line that starts with `#` is a comment.
fn fstests_tests() -> Result<Vec<String>> {
    // RK_FSTESTS_TESTS gives other arguments for a run by hand, for example `-g quick`.
    if let Ok(list) = std::env::var("RK_FSTESTS_TESTS") {
        return Ok(list.split_ascii_whitespace().map(String::from).collect());
    }
    let text = read(&workspace_root().join("tools/fstests/tests.txt"))?;
    Ok(text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(String::from)
        .collect())
}

/// The script that the `fstests` boot test runs as init. The first disk is the test device and
/// the second disk is the scratch device. The script makes an ext4 file system on the test device
/// and runs `check` with `tests`. The output of `check` goes to the console, with the difference
/// of the output and the end of the full log of each test that fails. `check` exits with 0
/// when no test fails. A test that does not apply does not fail.
fn fstests_script(tests: &[String]) -> String {
    let mut script = String::from(concat!(
        "#!/bin/sh\nexport PATH=/usr/sbin:/usr/bin:/sbin:/bin\n",
        "mount -t proc proc /proc\nmount -t tmpfs tmp /tmp\n",
        // resize2fs reads /sys/fs/ext4/features to grow a mounted file system.
        "mkdir -p /sys\nmount -t sysfs sysfs /sys\n",
        // bash makes `<(...)` with /dev/fd, which a distribution init makes on Linux.
        "[ -e /dev/fd ] || ln -s /proc/self/fd /dev/fd\n",
        // The overlay tests do not make the file system under the scratch overlay.
        "mkfs.ext4 -q -F /dev/vda\nmkfs.ext4 -q -F /dev/vdb\n",
        "cd /var/lib/xfstests\n",
        "RK_WATCH\n",
        "cat > local.config <<EOF\n",
        "export FSTYP=ext4\n",
        "export TEST_DEV=/dev/vda\nexport TEST_DIR=/test\n",
        "export SCRATCH_DEV=/dev/vdb\nexport SCRATCH_MNT=/scratch\n",
        "EOF\n",
        // The output of `check` goes to the console while the tests run, so the log of a
        // timeout shows the test that did not end.
        "{ ./check",
    ));
    // RK_FSTESTS_WATCH gives a time in seconds for a run by hand. After it, the script shows
    // the state and the system call of each process each minute, to find a test that hangs.
    let watch = std::env::var("RK_FSTESTS_WATCH").ok().and_then(|s| s.parse::<u64>().ok());
    let watch = watch.map_or(String::new(), |secs| {
        format!(
            "(sleep {secs}; while :; do for p in /proc/[0-9]*; do \
             echo \"watch: ${{p#/proc/}} $(cat $p/comm) $(cut -d' ' -f3 $p/stat) $(cat $p/syscall)\"; \
             done; sleep 60; done) 2>/dev/null &"
        )
    });
    script = script.replace("RK_WATCH", &watch);
    for t in tests {
        script.push(' ');
        script.push_str(t);
    }
    script.push_str(concat!(
        "; echo $? > /tmp/code; } 2>&1 | sed 's/^/fstests: /'\n",
        "code=$(cat /tmp/code)\n",
        // The difference of the output and the end of the full log of each test that failed.
        "for f in results/*/*.out.bad; do\n",
        "    [ -e \"$f\" ] || continue\n",
        "    t=${f#results/}; t=${t%.out.bad}\n",
        "    diff -u \"tests/$t.out\" \"$f\" | head -n 60\n",
        "    [ -e \"results/$t.full\" ] && tail -n 40 \"results/$t.full\"\n",
        "done 2>&1 | sed 's/^/fstests: /'\n",
        "exit $code\n",
    ));
    script
}

/// Writes the initramfs `initramfs-fstests.cpio` next to the kernel: the root file system of
/// tools/fstests/build.sh and the script of `fstests_script` as /init. Gives `false` if there is
/// no root file system.
fn build_fstests_initramfs(kernel: &Path) -> Result<bool> {
    let Some(fstests) = fstests_dir() else { return Ok(false) };
    let dir = kernel.parent().ok_or("the kernel path has no directory")?;
    let root = dir.join("fstests-root");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).map_err(|e| format!("{}: {e}", root.display()))?;
    let status = Command::new("tar")
        .arg("-xzf")
        .arg(fstests.join("rootfs.tar.gz"))
        .arg("-C")
        .arg(&root)
        .status()
        .map_err(|e| format!("cannot run tar: {e}"))?;
    if !status.success() {
        return Err(format!("tar cannot unpack {}", fstests.display()));
    }
    let mut w = rk_vfs::cpio::Writer::new();
    w.add(b".", 0o040_755, b"");
    add_tree(&mut w, &root, &root)?;
    w.add(b"init", 0o100_755, fstests_script(&fstests_tests()?).as_bytes());
    let path = kernel.with_file_name("initramfs-fstests.cpio");
    fs::write(&path, w.finish()).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(true)
}

/// Writes the initramfs `initramfs-NAME.cpio` of a boot test next to the kernel: BusyBox, the
/// programs of `dir` in `/NAME`, and `script` as `/NAME/run`. Gives `false` if the programs or
/// BusyBox are not there.
fn build_suite_initramfs(
    kernel: &Path,
    busybox: Option<&[u8]>,
    name: &str,
    dir: Option<PathBuf>,
    script: &str,
) -> Result<bool> {
    let (Some(dir), Some(busybox)) = (dir, busybox) else {
        return Ok(false);
    };
    let mut w = rk_vfs::cpio::Writer::new();
    w.add(b".", 0o040_755, b"");
    for d in ["bin", "tmp", "etc", name, "proc", "dev"] {
        w.add(d.as_bytes(), 0o040_755, b"");
    }
    w.add(b"bin/busybox", 0o100_755, busybox);
    for applet in BUSYBOX_APPLETS {
        w.add(format!("bin/{applet}").as_bytes(), 0o120_777, b"busybox");
    }
    w.add(b"etc/passwd", 0o100_644, b"root:x:0:0:root:/:/bin/sh\n");
    w.add(b"etc/group", 0o100_644, b"root:x:0:\n");
    let mut names = Vec::new();
    for entry in fs::read_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))? {
        let file = entry.map_err(|e| e.to_string())?.file_name();
        let file = file.to_string_lossy().into_owned();
        if file != "VERSION" {
            names.push(file);
        }
    }
    names.sort();
    for file in &names {
        let path = dir.join(file);
        let bytes = fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        w.add(format!("{name}/{file}").as_bytes(), 0o100_755, &bytes);
    }
    w.add(format!("{name}/run").as_bytes(), 0o100_755, script.as_bytes());
    let path = kernel.with_file_name(format!("initramfs-{name}.cpio"));
    fs::write(&path, w.finish()).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(true)
}

/// Writes the initramfs of the `ltp` boot test next to the kernel: BusyBox, the LTP tests and
/// the script. Gives `false` if LTP or BusyBox is not there.
fn build_ltp_initramfs(kernel: &Path, busybox: Option<&[u8]>) -> Result<bool> {
    let (Some(dir), Some(busybox)) = (ltp_dir(), busybox) else {
        return Ok(false);
    };
    let tests = ltp_tests()?;
    let mut w = rk_vfs::cpio::Writer::new();
    w.add(b".", 0o040_755, b"");
    for d in [&b"bin"[..], b"tmp", b"etc", b"ltp", b"proc"] {
        w.add(d, 0o040_755, b"");
    }
    w.add(b"bin/busybox", 0o100_755, busybox);
    for applet in BUSYBOX_APPLETS {
        w.add(format!("bin/{applet}").as_bytes(), 0o120_777, b"busybox");
    }
    w.add(
        b"etc/passwd",
        0o100_644,
        b"root:x:0:0:root:/:/bin/sh\nnobody:x:65534:65534:nobody:/:/bin/false\n",
    );
    w.add(b"etc/group", 0o100_644, b"root:x:0:\nnogroup:x:65534:\n");
    w.add(b"etc/kconfig", 0o100_644, read(&workspace_root().join("tools/ltp/kconfig"))?.as_bytes());
    for t in &tests {
        let path = dir.join(t);
        let bytes = fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        w.add(format!("ltp/{t}").as_bytes(), 0o100_755, &bytes);
    }
    w.add(b"ltp/run", 0o100_755, ltp_script(&tests).as_bytes());
    let path = kernel.with_file_name("initramfs-ltp.cpio");
    fs::write(&path, w.finish()).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(true)
}

/// Builds the x86-64 kernel and the initramfs of the boot tests, and gives the path of the ELF
/// image. The initramfs is in the same directory.
fn build_kernel() -> Result<PathBuf> {
    // RK_KERNEL_FEATURES selects features of the kernel, such as `corten` for the CortenMM
    // backend of rk-mm.
    let features = std::env::var("RK_KERNEL_FEATURES").unwrap_or_default();
    let mut args = vec!["build", "--package", "rukernel", "--target", "x86_64-unknown-none"];
    if !features.is_empty() {
        args.extend(["--features", features.as_str()]);
    }
    cargo(&args)?;
    let kernel = workspace_root().join("target/x86_64-unknown-none/debug/rukernel");
    let dir = kernel.parent().ok_or("the kernel path has no directory")?;
    let user = build_user(dir)?;
    let busybox = busybox(dir)?;
    let marker = kernel.with_file_name("busybox-ready");
    if busybox.is_some() {
        fs::write(&marker, b"").map_err(|e| format!("{}: {e}", marker.display()))?;
    } else {
        let _ = fs::remove_file(&marker);
    }
    let initramfs = kernel.with_file_name("initramfs.cpio");
    fs::write(&initramfs, test_initramfs(user.as_ref(), busybox.as_deref()))
        .map_err(|e| format!("{}: {e}", initramfs.display()))?;
    let ltp = kernel.with_file_name("initramfs-ltp.cpio");
    if !build_ltp_initramfs(&kernel, busybox.as_deref())? {
        let _ = fs::remove_file(&ltp);
    }
    let suites =
        [("kselftest", kselftest_dir(), KSELFTEST_SCRIPT), ("gvisor", gvisor_dir(), GVISOR_SCRIPT)];
    for (name, dir, script) in suites {
        if !build_suite_initramfs(&kernel, busybox.as_deref(), name, dir, script)? {
            let _ = fs::remove_file(kernel.with_file_name(format!("initramfs-{name}.cpio")));
        }
    }
    if !build_fstests_initramfs(&kernel)? {
        let _ = fs::remove_file(kernel.with_file_name("initramfs-fstests.cpio"));
    }
    for rootfs in ROOTFS {
        if !build_rootfs_initramfs(&kernel, rootfs)? {
            let _ = fs::remove_file(rootfs_initramfs(&kernel, rootfs.name));
        }
    }
    Ok(kernel)
}

/// The initramfs that the `initramfs` and `init` self tests read, per
/// kernel/rukernel/src/selftest.rs and tests/user/init.c. With no user programs, `/init` is a
/// script that cannot run. With BusyBox, /bin has BusyBox and a link for each applet of
/// `BUSYBOX_APPLETS`.
fn test_initramfs(user: Option<&(Vec<u8>, Vec<u8>)>, busybox: Option<&[u8]>) -> Vec<u8> {
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
    if let Some(busybox) = busybox {
        if user.is_none() {
            w.add(b"bin", 0o040_755, b"");
        }
        w.add(b"bin/busybox", 0o100_755, busybox);
        for applet in BUSYBOX_APPLETS {
            w.add(format!("bin/{applet}").as_bytes(), 0o120_777, b"busybox");
        }
    }
    w.finish()
}

/// The physical address where the loader puts the payload of the bzImage. The bzImage is not
/// relocatable, so the loader always puts it at 1 MiB.
const BZIMAGE_LOAD: u64 = 0x10_0000;
/// The physical address where the kernel runs, as `CONFIG_PHYSICAL_START` of Linux. The entry code
/// in `boot.rs` moves the payload from `BZIMAGE_LOAD` to this address. x86_64.ld has this value.
const KERNEL_PHYS: u64 = 0x100_0000;
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
/// `PT_LOAD` segments as one flat image from `KERNEL_PHYS`.
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
            if paddr < KERNEL_PHYS {
                return Err(format!("a segment is at {paddr:#x}, below {KERNEL_PHYS:#x}"));
            }
            segments.push((offset, paddr, filesz, memsz));
        }
    }
    let file_end = segments.iter().map(|s| s.1 + s.2).max().ok_or("the kernel has no segments")?;
    let mem_end = segments.iter().map(|s| s.1 + s.3).max().unwrap_or(file_end);
    let mut payload = vec![0; usize_of(file_end - KERNEL_PHYS)?.next_multiple_of(PE_FILE_ALIGN)];
    for &(offset, paddr, filesz, _) in &segments {
        let (at, len) = (usize_of(paddr - KERNEL_PHYS)?, usize_of(filesz)?);
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
    put::<8>(&mut image, 0x258, KERNEL_PHYS); // pref_address
    // init_size: from the load address to the end of the kernel at `KERNEL_PHYS`, so that a 64 bit
    // loader maps both copies of the image in its identity map.
    put::<4>(&mut image, 0x260, (mem_end - BZIMAGE_LOAD).next_multiple_of(4096));
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
    qemu_command_with(kernel, &kernel.with_file_name("initramfs.cpio"), cmdline)
}

/// The size of the disk of the `blk` boot test.
const BLK_DISK_SIZE: usize = 1 << 20;
/// The size of the disk that the `alpine` test makes an ext4 file system on.
const EXT4_DISK_SIZE: u64 = 64 << 20;
/// The size of the disk that the `alpine` test makes an XFS file system on. mkfs.xfs does not make
/// a file system smaller than 300 MiB.
const XFS_DISK_SIZE: u64 = 320 << 20;
/// The text that the `blk` test writes at `BLK_NOTE_AT`. tests/user/init.c has the same values.
const BLK_NOTE: &[u8] = b"rukernel wrote this sector";
const BLK_NOTE_AT: usize = 512 * 9 + 100;
/// The range that the `blk` test writes through the page cache before `sync`, and the byte at
/// offset k of it.
const BLK_CACHED_AT: usize = 512 << 10;
const BLK_CACHED_LEN: usize = 512 << 10;
fn blk_cached_byte(k: usize) -> u8 {
    (k * 13 + k / 4096) as u8
}

/// Writes the disk of the `blk` boot test. The byte at offset k has a value from k, so that the
/// guest can check each byte that it reads.
fn write_blk_disk(path: &Path) -> Result {
    let data: Vec<u8> = (0..BLK_DISK_SIZE).map(|k| (k / 512 * 7 + k % 251) as u8).collect();
    fs::write(path, data).map_err(|e| format!("cannot write {}: {e}", path.display()))
}

/// Tells if the guest wrote its text, and the data that it wrote through the page cache, to the
/// disk of the `blk` boot test.
fn blk_disk_has_note(path: &Path) -> Result<bool> {
    let data = fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let cached = data.get(BLK_CACHED_AT..BLK_CACHED_AT + BLK_CACHED_LEN).is_some_and(|d| {
        d.iter().enumerate().all(|(k, &b)| b == blk_cached_byte(BLK_CACHED_AT + k))
    });
    Ok(data.get(BLK_NOTE_AT..BLK_NOTE_AT + BLK_NOTE.len()) == Some(BLK_NOTE) && cached)
}

/// The number of CPUs of the `smp` boot test.
///
/// The kernel has one lock, so more CPUs make it slower on a host with few free CPUs. On a host
/// with 6 CPUs and a load of 7 to 10, the `smp` test took 322 s with 8 CPUs and 112 s with 4
/// CPUs (#396). With 4 CPUs, the test still runs tasks on several CPUs at the same time.
const SMP_CPUS: &str = "4";

/// The QEMU command for the x86-64 kernel with the initramfs `initrd`. The machine has one CPU, or
/// the number of CPUs in `RK_SMP`. The `smp` boot test has `SMP_CPUS` CPUs.
fn qemu_command_with(kernel: &Path, initrd: &Path, cmdline: &str) -> Command {
    let smp = if cmdline.ends_with("-- smp") {
        String::from(SMP_CPUS)
    } else {
        std::env::var("RK_SMP").unwrap_or_else(|_| String::from("1"))
    };
    let mut cmd = Command::new("qemu-system-x86_64");
    cmd.args(["-machine", "q35", "-m", "512M", "-smp", &smp, "-display", "none"])
        .args(["-serial", "stdio", "-no-reboot", "-monitor", "none"])
        .args(["-device", "isa-debug-exit,iobase=0xf4,iosize=0x04"])
        .arg("-kernel")
        .arg(kernel)
        .arg("-initrd")
        .arg(initrd)
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

/// Tells if the boot test `test` can run. The `init` and `tty` tests need the user programs, and
/// the `busybox` test needs BusyBox.
fn can_run(kernel: &Path, test: &str) -> bool {
    match test {
        "init" | "tty" | "smp" | "blk" | "inet" => kernel.with_file_name("user-init").exists(),
        "busybox" | "netcfg" | "inet6" | "netns" => kernel.with_file_name("busybox-ready").exists(),
        "ltp" => kernel.with_file_name("initramfs-ltp.cpio").exists(),
        "kselftest" | "gvisor" | "fstests" => {
            kernel.with_file_name(format!("initramfs-{test}.cpio")).exists()
        }
        t if ROOTFS.iter().any(|r| r.name == t) => rootfs_initramfs(kernel, t).exists(),
        _ => true,
    }
}

/// The size of the data that the `inet` test sends in each direction over TCP.
const TCP_BYTES: usize = 1 << 20;

/// The byte `i` of the data of the TCP test. Pattern 0 goes from the guest to the host, and
/// pattern 1 goes back. `tcp_pattern` of tests/user/init.c gives the same bytes.
fn tcp_pattern(i: usize, b: u8) -> u8 {
    if b == 1 { (i * 13 + (i >> 8) + 5) as u8 } else { (i * 7 + (i >> 10)) as u8 }
}

/// The 64-bit FNV-1a hash, as `fnv` of tests/user/init.c.
fn fnv(mut h: u64, data: &[u8]) -> u64 {
    for &b in data {
        h = (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3);
    }
    h
}

/// The TCP server on the host for the `inet` test. It accepts one connection from the guest,
/// reads to the end of the stream and checks the data. Then it sends the hash of the data in 8
/// bytes (little endian) and 1 MiB of pattern 1.
struct TcpServer {
    /// The port of the server on 127.0.0.1. The guest connects to 10.0.2.2 and this port.
    port: u16,
    /// The result of the thread of the server.
    done: std::sync::mpsc::Receiver<Result>,
}

impl TcpServer {
    /// Starts the server on a free port.
    fn start() -> Result<Self> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
        let port = listener.local_addr().map_err(|e| e.to_string())?.port();
        let (tx, done) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(Self::serve(&listener));
        });
        Ok(Self { port, done })
    }

    /// Serves one connection.
    fn serve(listener: &std::net::TcpListener) -> Result {
        let (mut conn, _) = listener.accept().map_err(|e| format!("accept: {e}"))?;
        conn.set_read_timeout(Some(BOOT_TEST_TIMEOUT)).map_err(|e| e.to_string())?;
        let mut data = Vec::new();
        conn.read_to_end(&mut data).map_err(|e| format!("read: {e}"))?;
        if data.len() != TCP_BYTES {
            return Err(format!("got {} bytes, not {TCP_BYTES}", data.len()));
        }
        if let Some(i) = data.iter().enumerate().position(|(i, &b)| b != tcp_pattern(i, 0)) {
            return Err(format!("byte {i} is not correct"));
        }
        let sum = fnv(0xcbf2_9ce4_8422_2325, &data);
        let reply: Vec<u8> = (0..TCP_BYTES).map(|i| tcp_pattern(i, 1)).collect();
        conn.write_all(&sum.to_le_bytes()).map_err(|e| format!("write: {e}"))?;
        conn.write_all(&reply).map_err(|e| format!("write: {e}"))?;
        Ok(())
    }

    /// The result of the server. The guest is done, so the server is done or it did not get a
    /// connection.
    fn result(self) -> Result {
        match self.done.recv_timeout(Duration::from_secs(5)) {
            Ok(r) => r,
            Err(_) => Err(String::from("no connection from the guest")),
        }
    }
}

/// The command line of a boot test. The `tty` test runs init with the argument `tty`, which is
/// after `--`, as Linux gives the arguments of init.
fn test_cmdline(test: &str) -> String {
    match test {
        "tty" => String::from("console=ttyS0 rk.test=init -- tty"),
        "smp" => String::from("console=ttyS0 rk.test=init -- smp"),
        "blk" => String::from("console=ttyS0 rk.test=init -- blk"),
        // The address, the netmask and the gateway of the user network of QEMU.
        "inet" => {
            String::from("console=ttyS0 rk.test=init ip=10.0.2.15::10.0.2.2:255.255.255.0 -- inet")
        }
        "busybox" | "netcfg" | "inet6" | "netns" => {
            String::from("console=ttyS0 rk.test=init rdinit=/bin/sh -- -i")
        }
        "ltp" => String::from("console=ttyS0 rk.test=init rdinit=/ltp/run"),
        "kselftest" => String::from("console=ttyS0 rk.test=init rdinit=/kselftest/run"),
        "gvisor" => String::from("console=ttyS0 rk.test=init rdinit=/gvisor/run"),
        t if t == "fstests" || ROOTFS.iter().any(|r| r.name == t) => {
            String::from("console=ttyS0 rk.test=init rdinit=/init")
        }
        _ => format!("console=ttyS0 rk.test={test}"),
    }
}

/// The line that the kernel prints when the boot test `test` passes.
fn pass_line(test: &str) -> String {
    let test = if matches!(
        test,
        "tty"
            | "smp"
            | "blk"
            | "inet"
            | "netcfg"
            | "inet6"
            | "netns"
            | "busybox"
            | "ltp"
            | "kselftest"
            | "gvisor"
            | "fstests"
    ) || ROOTFS.iter().any(|r| r.name == test)
    {
        "init"
    } else {
        test
    };
    format!("rk.test={test}: pass")
}

/// The commands of the `netcfg` test. The shell sets up the interface of the user network of
/// QEMU without `ip=`, through rtnetlink (`ip`) and the interface ioctls (`ifconfig`, `route`).
/// Then it pings the gateway, looks up routes, and reads the files of /proc/net, the socket
/// tables and /sys/class/net. The line editor of BusyBox takes at most 1024 bytes, so the
/// commands are in two lines. The shell exits with 0 only if all of the commands pass.
const NETCFG_SCRIPT: &[u8] = b"mkdir -p /proc && mount -t proc proc /proc \
&& ip link set lo up && ip link set eth0 up \
&& ip addr add 10.0.2.15/24 dev eth0 && ip route add default via 10.0.2.2 \
&& ip link && ip addr && ip route && ip route show table local \
&& ip addr add 10.0.2.16/24 dev eth0 && ip addr del 10.0.2.16/24 dev eth0 \
&& ifconfig && ifconfig eth0 mtu 1400 && ifconfig eth0 | grep -q MTU:1400 \
&& ifconfig eth0:1 10.0.3.1 netmask 255.255.255.0 && ifconfig eth0:1 down \
&& route add -net 10.9.0.0 netmask 255.255.0.0 gw 10.0.2.2 mss 1400 window 8192 irtt 10 \
&& route -n && ip route show 10.9.0.0/16 && cat /proc/net/route \
&& grep -q '^eth0.0000090A.*0000FFFF.1400.8192.10 ' /proc/net/route \
&& route del -net 10.9.0.0 netmask 255.255.0.0 && ! ip route | grep -q 10.9.0.0 \
&& ping -c 1 10.0.2.2 && ip neigh && ls /proc/net \
&& cat /proc/net/dev /proc/net/route /proc/net/arp /proc/net/snmp /proc/net/netstat \
&& grep -q '^Icmp: [1-9]' /proc/net/snmp && echo 'netcfg: first'' part' || exit 1\n";

/// The second line of the `netcfg` test, after the text of `NETCFG_SCRIPT` that ends the first.
const NETCFG_SCRIPT2: &[u8] =
    b"ip route get 10.0.2.2 && ip route get 1.1.1.1 | grep -q 'via 10.0.2.2' \
&& ip route get 127.0.0.1 | grep -q '^local' \
&& { busybox tcpsvd 0 5555 true </dev/null & } && { busybox udpsvd 0 5556 true </dev/null & } \
&& { for i in 1 2 3 4 5 6 7 8 9 10; do grep -q :15B4 /proc/net/udp && break; sleep 1; done; } \
&& cat /proc/net/tcp /proc/net/udp /proc/net/raw /proc/net/icmp /proc/net/unix \
&& grep -q ': 00000000:15B3 00000000:0000 0A ' /proc/net/tcp \
&& grep -q ': 00000000:15B4 00000000:0000 07 ' /proc/net/udp \
&& grep -q '^Num       RefCount Protocol Flags    Type St Inode Path' /proc/net/unix \
&& mkdir -p /sys && mount -t sysfs sysfs /sys && ls /sys/class/net /sys/class/net/eth0 \
&& cat /sys/class/net/eth0/address /sys/class/net/eth0/operstate \
&& grep -q 1400 /sys/class/net/eth0/mtu && cat /sys/class/net/lo/statistics/rx_packets \
&& grep VmData /proc/self/status && exit 0; exit 1\n";

/// The commands of the `inet6` test. The shell brings up lo and the interface of the user network
/// of QEMU, and checks the address `::1` and the link local address that the kernel makes from
/// the MAC address. It pings `::1`, waits for the address that the router advertisement of QEMU
/// gives (SLAAC), and pings the router on the link local address and on the global address.
const INET6_SCRIPT: &[u8] = b"mkdir -p /proc && mount -t proc proc /proc \
&& ip link set lo up && ip link set eth0 up && ip -6 addr && ip -6 route \
&& ip -6 addr show dev lo | grep -q 'inet6 ::1/128 scope host' \
&& ip -6 addr show dev eth0 | grep -q 'inet6 fe80::5054:ff:fe12:3456/64 scope link' \
&& busybox ping6 -c 1 ::1 \
&& { for i in 1 2 3 4 5 6 7 8 9 10; do ip -6 addr | grep -q fec0:: && break; sleep 1; done; } \
&& { for i in 1 2 3 4 5 6 7 8 9 10; do ip -6 route | grep -q ^default && break; sleep 1; done; } \
&& ip -6 addr && ip -6 route && ip -6 route show table local \
&& ip -6 addr show dev eth0 | grep -q 'inet6 fec0::5054:ff:fe12:3456/64 scope site' \
&& ip -6 route | grep -q '^default via fe80::2 dev eth0' \
&& busybox ping6 -c 1 fe80::2%eth0 && busybox ping6 -c 1 fec0::2 && ip -6 neigh \
&& ip -6 route get fec0::2 | grep -q 'dev eth0' \
&& echo 'inet6: first'' part' || exit 1\n";

/// The second line of the `inet6` test. It adds and deletes an address and a route through
/// rtnetlink, and reads the IPv6 files of /proc/net.
const INET6_SCRIPT2: &[u8] = b"ip -6 addr add 2001:db8:1::5/64 dev eth0 \
&& ip -6 addr show dev eth0 | grep -q 2001:db8:1::5/64 && busybox ping6 -c 1 2001:db8:1::5 \
&& ip -6 addr del 2001:db8:1::5/64 dev eth0 && ! ip -6 addr | grep -q 2001:db8:1:: \
&& ip -6 route add 2001:db8:9::/48 via fe80::2 dev eth0 \
&& ip -6 route | grep -q '^2001:db8:9::/48 via fe80::2 dev eth0' \
&& ip -6 route del 2001:db8:9::/48 via fe80::2 dev eth0 && ! ip -6 route | grep -q 2001:db8:9:: \
&& cat /proc/net/if_inet6 /proc/net/ipv6_route /proc/net/snmp6 \
&& grep -q '^00000000000000000000000000000001 01 80 10 80 *lo$' /proc/net/if_inet6 \
&& grep -q '^fe80000000000000505400fffe123456 02 40 20 ' /proc/net/if_inet6 \
&& grep -q '^Icmp6InEchoReplies[[:space:]]*[1-9]' /proc/net/snmp6 \
&& echo 'inet6: second'' part' || exit 1\n";

/// The third line of the `inet6` test. It runs a TCP server and a UDP server on `::` and finds
/// them in /proc/net/tcp6 and /proc/net/udp6. A TCP client connects to the server on `::1`.
const INET6_SCRIPT3: &[u8] = b"{ busybox tcpsvd :: 5557 echo v6ok </dev/null & } && { busybox udpsvd :: 5558 true </dev/null & } \
&& { for i in 1 2 3 4 5 6 7 8 9 10; do grep -q :15B6 /proc/net/udp6 && break; sleep 1; done; } \
&& cat /proc/net/tcp6 /proc/net/udp6 /proc/net/raw6 \
&& grep -q ': 0*:15B5 0*:0000 0A ' /proc/net/tcp6 \
&& grep -q ': 0*:15B6 0*:0000 07 ' /proc/net/udp6 \
&& busybox nc -w 3 ::1 5557 </dev/null | grep -q v6ok && exit 0; exit 1\n";

/// The commands of the `netns` test. The shell starts two processes, each in a new network
/// namespace, and checks their files in /proc/PID/ns. It makes a veth pair and moves one end into
/// each namespace. Then the network of one namespace must not show in the other.
const NETNS_SCRIPT: &[u8] = b"mkdir -p /proc && mount -t proc proc /proc && ip link set lo up \
&& { busybox unshare -n sleep 1000 & } && A=$! && { busybox unshare -n sleep 1000 & } && B=$! \
&& sleep 1 && N='busybox nsenter -n -t' && busybox readlink /proc/$A/ns/net \
&& busybox readlink /proc/$A/ns/net | grep -q '^net:\\[[0-9]*\\]$' \
&& test \"$(busybox readlink /proc/$A/ns/net)\" != \"$(busybox readlink /proc/self/ns/net)\" \
&& test \"$(busybox readlink /proc/$A/ns/net)\" != \"$(busybox readlink /proc/$B/ns/net)\" \
&& ip link add va type veth && ip link && ip link show veth0 \
&& ip link set va netns $A && ip link set veth0 netns $B && ip link && ! ip link | grep -q veth \
&& $N $A ip link && $N $A ip link show va && ! $N $A ip link show veth0 \
&& $N $B ip link show veth0 && ! $N $B ip link show va \
&& echo 'netns: first'' part' || exit 1\n";

/// The second line of the `netns` test. It gives addresses to the two ends and pings across the
/// pair with IPv4 and IPv6. The first namespace cannot reach the addresses.
const NETNS_SCRIPT2: &[u8] = b"$N $A ip link set lo up && $N $A ip link set va up \
&& $N $B ip link set lo up && $N $B ip link set veth0 up \
&& $N $A ip addr add 10.9.0.1/24 dev va && $N $B ip addr add 10.9.0.2/24 dev veth0 \
&& $N $A ip -6 addr add fd00::1/64 dev va && $N $B ip -6 addr add fd00::2/64 dev veth0 \
&& $N $A ip addr && $N $A ip route && $N $B ip -6 route \
&& $N $A ping -c 1 10.9.0.2 && $N $B ping -c 1 10.9.0.1 \
&& $N $A busybox ping6 -c 1 fd00::2 && $N $B busybox ping6 -c 1 fd00::1 \
&& $N $A ip neigh && $N $A cat /proc/net/dev /proc/net/route /proc/net/snmp \
&& $N $A grep -q '^Icmp: [1-9]' /proc/net/snmp && ! grep -q va /proc/net/dev \
&& ! ip route | grep -q 10.9.0 && ! ping -c 1 -W 1 10.9.0.2 \
&& echo 'netns: second'' part' || exit 1\n";

/// The third line of the `netns` test. The sysctls of /proc/sys/net and a dummy device are in
/// one namespace only.
const NETNS_SCRIPT_SYSCTL: &[u8] = b"$N $A cat /proc/sys/net/ipv6/conf/va/disable_ipv6 \
&& ! test -e /proc/sys/net/ipv6/conf/va \
&& $N $A sh -c 'echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all' \
&& ! $N $B ping -c 1 -W 1 10.9.0.1 && grep -q 0 /proc/sys/net/ipv4/icmp_echo_ignore_all \
&& $N $A ip link add d0 type dummy && $N $A ip link show d0 && ! ip link show d0 \
&& echo 'netns: third'' part' || exit 1\n";

/// The last line of the `netns` test. When the two processes end, the namespaces go, and the
/// veth pair goes with them.
const NETNS_SCRIPT3: &[u8] = b"kill $A $B; wait; sleep 1; ip link \
&& ! ip link | grep -q veth && test \"$(ip link | grep -c mtu)\" = 1 && exit 0; exit 1\n";

/// The input of a boot test. When the log has the text of an entry, the test writes the bytes of
/// the entry to the serial port. The `tty` test types a line and then `^C`.
fn test_input(test: &str) -> &'static [(&'static str, &'static [u8])] {
    match test {
        "tty" => &[("init: type a line", b"hello\n"), ("init: press ^C", b"\x03")],
        // The shell runs a pipeline, then a job in the foreground. `^C` stops the job, and the
        // shell exits with 0 if the job ended with `SIGINT`. The quotes keep the echo of the
        // typed line different from the output.
        "busybox" => &[
            ("/ # ", b"echo one two | tr a-z A-Z | cat\n"),
            ("ONE TWO", b"sh -c 'while :; do echo T\"ICK\"; sleep 1; done'\n"),
            ("TICK", b"\x03"),
            ("TICK", b"test $? = 130; exit $?\n"),
        ],
        "netcfg" => &[("/ # ", NETCFG_SCRIPT), ("netcfg: first part", NETCFG_SCRIPT2)],
        "netns" => &[
            ("/ # ", NETNS_SCRIPT),
            ("netns: first part", NETNS_SCRIPT2),
            ("netns: second part", NETNS_SCRIPT_SYSCTL),
            ("netns: third part", NETNS_SCRIPT3),
        ],
        "inet6" => &[
            ("/ # ", INET6_SCRIPT),
            ("inet6: first part", INET6_SCRIPT2),
            ("inet6: second part", INET6_SCRIPT3),
        ],
        _ => &[],
    }
}

/// Runs the boot tests. With no names, it runs all of the x86-64 tests and then the arm64 tests.
/// The name `aarch64` selects the arm64 tests, and the other names select x86-64 tests.
fn boot_test(names: &[String]) -> Result {
    if let Some(name) = names.iter().find(|n| *n != "aarch64" && !BOOT_TESTS.contains(&n.as_str()))
    {
        return Err(format!("{name}: no such boot test"));
    }
    let arm = names.iter().any(|n| n == "aarch64");
    let x86: Vec<String> = names.iter().filter(|n| *n != "aarch64").cloned().collect();
    let mut errors = Vec::new();
    if !arm || !x86.is_empty() {
        x86_boot_tests(&x86, &mut errors)?;
    }
    if arm || names.is_empty() {
        aarch64_boot_tests(&mut errors)?;
    }
    report("boot tests", errors)
}

/// Runs the x86-64 boot tests with the names, or all of them, and adds the failures to `errors`.
fn x86_boot_tests(names: &[String], errors: &mut Vec<String>) -> Result {
    let kernel = build_kernel()?;
    let named = |t: &&&str| names.is_empty() || names.iter().any(|n| n == **t);
    for test in BOOT_TESTS.iter().filter(named).filter(|t| can_run(&kernel, t)) {
        // The `inet` test connects to a TCP server on the host. The guest gets the port on the
        // command line of init.
        let server = if *test == "inet" { Some(TcpServer::start()?) } else { None };
        let (mut cmd, timeout) = if *test == "ltp" {
            let initrd = kernel.with_file_name("initramfs-ltp.cpio");
            let mut cmd = qemu_command_with(&kernel, &initrd, &test_cmdline(test));
            let disk = kernel.with_file_name("ltp.img");
            let file = fs::File::create(&disk).map_err(|e| format!("{}: {e}", disk.display()))?;
            file.set_len(LTP_DISK_SIZE).map_err(|e| format!("{}: {e}", disk.display()))?;
            cmd.arg("-drive")
                .arg(format!("if=none,id=ltp,format=raw,cache=unsafe,file={}", disk.display()))
                .args(["-device", "virtio-blk-pci,drive=ltp"]);
            (cmd, LTP_TIMEOUT)
        } else if *test == "kselftest" || *test == "gvisor" {
            let initrd = kernel.with_file_name(format!("initramfs-{test}.cpio"));
            let timeout = if *test == "gvisor" { GVISOR_TIMEOUT } else { KSELFTEST_TIMEOUT };
            (qemu_command_with(&kernel, &initrd, &test_cmdline(test)), timeout)
        } else if *test == "fstests" {
            let initrd = kernel.with_file_name("initramfs-fstests.cpio");
            let mut cmd = qemu_command_with(&kernel, &initrd, &test_cmdline(test));
            // QEMU uses the last `-m`.
            cmd.args(["-m", FSTESTS_MEMORY]);
            for name in ["test", "scratch"] {
                let disk = kernel.with_file_name(format!("fstests-{name}.img"));
                let file =
                    fs::File::create(&disk).map_err(|e| format!("{}: {e}", disk.display()))?;
                file.set_len(FSTESTS_DISK_SIZE).map_err(|e| format!("{}: {e}", disk.display()))?;
                cmd.arg("-drive")
                    .arg(format!(
                        "if=none,id={name},format=raw,cache=unsafe,file={}",
                        disk.display()
                    ))
                    .args(["-device", &format!("virtio-blk-pci,drive={name}")]);
            }
            // RK_FSTESTS_TIMEOUT gives a shorter time in seconds for a run by hand.
            let timeout = std::env::var("RK_FSTESTS_TIMEOUT")
                .ok()
                .and_then(|s| s.parse().ok())
                .map_or(FSTESTS_TIMEOUT, Duration::from_secs);
            (cmd, timeout)
        } else if ROOTFS.iter().any(|r| r.name == *test) {
            let initrd = rootfs_initramfs(&kernel, test);
            (qemu_command_with(&kernel, &initrd, &test_cmdline(test)), ROOTFS_TIMEOUT)
        } else if let Some(server) = &server {
            let cmdline = format!("{} {}", test_cmdline(test), server.port);
            (qemu_command(&kernel, &cmdline), BOOT_TEST_TIMEOUT)
        } else {
            let cmdline = test_cmdline(test);
            let timeout = if *test == "smp" {
                SMP_TEST_TIMEOUT
            } else if cmdline.contains("rk.test=init") {
                INIT_TEST_TIMEOUT
            } else {
                BOOT_TEST_TIMEOUT
            };
            (qemu_command(&kernel, &cmdline), timeout)
        };
        // The `alpine` test runs fio on the disk.
        if matches!(*test, "blk" | "alpine") {
            let disk = kernel.with_file_name("blk.img");
            write_blk_disk(&disk)?;
            cmd.arg("-drive")
                .arg(format!("if=none,id=disk0,format=raw,file={}", disk.display()))
                .args(["-device", "virtio-blk-pci,drive=disk0"]);
        }
        // The `net` test sends an ARP request to the gateway of the user network of QEMU. The
        // `inet` test pings the gateway and asks the DNS server of QEMU. The `netcfg` test sets up
        // the network with BusyBox. The `inet6` test uses the IPv6 network of QEMU: the prefix
        // fec0::/64 and the router fec0::2.
        if matches!(*test, "net" | "inet" | "netcfg" | "inet6") {
            cmd.args(["-netdev", "user,id=n0", "-device", "virtio-net-pci,netdev=n0"]);
        }
        // The `alpine` test makes an ext4 file system on a second disk and mounts it.
        if *test == "alpine" {
            let disk = kernel.with_file_name("ext4.img");
            let file = fs::File::create(&disk).map_err(|e| format!("{}: {e}", disk.display()))?;
            file.set_len(EXT4_DISK_SIZE).map_err(|e| format!("{}: {e}", disk.display()))?;
            cmd.arg("-drive")
                // The disk is new for each run, so a flush does not have to reach the host disk.
                .arg(format!("if=none,id=disk1,format=raw,cache=unsafe,file={}", disk.display()))
                .args(["-device", "virtio-blk-pci,drive=disk1"]);
            // And it makes an XFS file system on a third disk.
            let disk = kernel.with_file_name("xfs.img");
            let file = fs::File::create(&disk).map_err(|e| format!("{}: {e}", disk.display()))?;
            file.set_len(XFS_DISK_SIZE).map_err(|e| format!("{}: {e}", disk.display()))?;
            cmd.arg("-drive")
                .arg(format!("if=none,id=disk2,format=raw,cache=unsafe,file={}", disk.display()))
                .args(["-device", "virtio-blk-pci,drive=disk2"]);
        }
        let (status, log) = run_with_timeout(cmd, timeout, test_input(test))?;
        let mut passed = status == Some(QEMU_PASS) && log.contains(&pass_line(test));
        if *test == "blk" && passed && !blk_disk_has_note(&kernel.with_file_name("blk.img"))? {
            println!("boot test blk: the disk image does not have the data that the guest wrote");
            passed = false;
        }
        if passed
            && let Some(server) = server
            && let Err(e) = server.result()
        {
            println!("boot test {test}: the TCP server on the host: {e}");
            passed = false;
        }
        if passed {
            println!("boot test {test}: pass");
            // RK_BOOT_LOG shows all of the log of a test that passes, for a run by hand.
            if std::env::var_os("RK_BOOT_LOG").is_some() {
                println!("{log}");
            }
            // The kselftest and gVisor totals show the tests that the kernel skips.
            let totals = |l: &&str| {
                l.starts_with("kselftest: ")
                    || l.starts_with("gvisor: ")
                    || l.starts_with("fstests: ")
            };
            for line in log.lines().filter(totals) {
                println!("{line}");
            }
        } else {
            let status = status.map_or(String::from("a timeout"), |s| format!("status {s}"));
            errors.push(format!("boot test {test}: fail with {status}\n{log}"));
        }
    }
    let bzimage = build_bzimage()?;
    for test in BZIMAGE_TESTS.iter().filter(named).filter(|t| can_run(&kernel, t)) {
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
            for test in BZIMAGE_TESTS.iter().filter(named).filter(|t| can_run(&kernel, t)) {
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
    Ok(())
}

/// The self tests that `boot-test aarch64` runs on the QEMU `virt` machine, each in its own boot.
/// The `boot` test shows the first console line and starts `AARCH64_SMP_CPUS` CPUs, and the
/// `timer` test waits for timer ticks.
const AARCH64_TESTS: &[&str] =
    &["boot", "trap", "mm", "heap", "timer", "task", "syscall", "vm", "fault"];

/// The tests that `boot-test aarch64` runs with the user programs of tests/user in the initramfs,
/// as the x86-64 tests of the same names. They need `find_user_cc_aarch64`. The `busybox` test
/// also needs an arm64 BusyBox from `RK_BUSYBOX_AARCH64`, which tools/busybox/build.sh makes. The
/// `blk` and `inet` tests run two times: with the virtio-mmio devices of the `virt` machine, and
/// with virtio-pci devices on the PCI bus of the ECAM host.
const AARCH64_USER_TESTS: &[&str] = &["init", "smp", "blk", "inet", "busybox"];

/// The time limit of each test of `AARCH64_USER_TESTS`. QEMU emulates each instruction, and the
/// `init` test runs all of the general checks of init.
const AARCH64_USER_TIMEOUT: Duration = Duration::from_secs(1500);

/// The command line of the arm64 boot test `test`. The `smp`, `blk` and `inet` tests give init
/// the argument `only`, so that init does not run the general checks again. The `init` test runs
/// them.
fn aarch64_cmdline(test: &str) -> String {
    let cmdline = test_cmdline(test).replace("console=ttyS0", "console=ttyAMA0");
    if matches!(test, "smp" | "blk" | "inet") {
        cmdline.replace(" -- ", " -- only ")
    } else {
        cmdline
    }
}

/// The input of the arm64 `busybox` test, as `test_input("busybox")`. The BusyBox of Alpine shows
/// the prompt `~ # ` in the root directory, not `/ # `.
const AARCH64_BUSYBOX_INPUT: &[(&str, &[u8])] = &[
    ("~ # ", b"echo one two | tr a-z A-Z | cat\n"),
    ("ONE TWO", b"sh -c 'while :; do echo T\"ICK\"; sleep 1; done'\n"),
    ("TICK", b"\x03"),
    ("TICK", b"test $? = 130; exit $?\n"),
];

/// The number of CPUs of the arm64 `boot` test. The other arm64 tests have one CPU.
const AARCH64_SMP_CPUS: &str = "4";

/// The offset and the value of the magic number in the header of a Linux arm64 `Image`, per
/// Documentation/arch/arm64/booting.rst of Linux.
const IMAGE_MAGIC_AT: usize = 0x38;
const IMAGE_MAGIC: u64 = 0x644d_5241;

/// Makes a Linux arm64 `Image` from the kernel ELF file. The physical address of each segment is
/// its offset in the image, and the bss is not in the file.
fn arm64_image(elf: &[u8]) -> Result<Vec<u8>> {
    if elf.get(..4) != Some(b"\x7fELF".as_slice()) || elf.get(4) != Some(&2) {
        return Err(String::from("the kernel is not an ELF64 file"));
    }
    let usize_of = |v: u64| usize::try_from(v).map_err(|e| e.to_string());
    let (phoff, phentsize, phnum) =
        (usize_of(le::<8>(elf, 0x20)?)?, usize_of(le::<2>(elf, 0x36)?)?, le::<2>(elf, 0x38)?);
    let mut image = Vec::new();
    for i in 0..usize_of(phnum)? {
        let ph = phoff + i * phentsize;
        if le::<4>(elf, ph)? != 1 {
            continue;
        }
        let offset = usize_of(le::<8>(elf, ph + 8)?)?;
        let (at, len) = (usize_of(le::<8>(elf, ph + 24)?)?, usize_of(le::<8>(elf, ph + 32)?)?);
        let data = elf.get(offset..offset + len).ok_or("a segment is outside the file")?;
        if image.len() < at + len {
            image.resize(at + len, 0);
        }
        image[at..at + len].copy_from_slice(data);
    }
    if le::<4>(&image, IMAGE_MAGIC_AT)? != IMAGE_MAGIC {
        return Err(String::from("the kernel does not start with an arm64 Image header"));
    }
    Ok(image)
}

/// Builds the arm64 user programs of tests/user and the initramfs of the user tests next to the
/// kernel `elf`. The initramfs has the arm64 BusyBox from `RK_BUSYBOX_AARCH64` if the variable is
/// set. Gives the path of the initramfs and whether it has BusyBox, or `None` if there is no arm64
/// C compiler.
fn aarch64_initramfs(elf: &Path) -> Result<Option<(PathBuf, bool)>> {
    let Some(cc) = find_user_cc_aarch64() else {
        println!("user programs on arm64: skipped, no C compiler, set RK_USER_CC_AARCH64");
        return Ok(None);
    };
    let (init, hello) = (elf.with_file_name("user-init"), elf.with_file_name("user-hello"));
    compile_user(&cc, "init", false, &init)?;
    compile_user(&cc, "hello", true, &hello)?;
    let read = |p: &Path| fs::read(p).map_err(|e| format!("{}: {e}", p.display()));
    let initrd = elf.with_file_name("initramfs.cpio");
    let user = (read(&init)?, read(&hello)?);
    let busybox = match std::env::var_os("RK_BUSYBOX_AARCH64") {
        Some(path) => Some(read(Path::new(&path))?),
        None => None,
    };
    fs::write(&initrd, test_initramfs(Some(&user), busybox.as_deref()))
        .map_err(|e| format!("{}: {e}", initrd.display()))?;
    Ok(Some((initrd, busybox.is_some())))
}

/// Builds the arm64 kernel and runs `AARCH64_TESTS`, and `AARCH64_USER_TESTS` with a C compiler,
/// on `qemu-system-aarch64 -M virt`, and adds the failures to `errors`. Without QEMU for arm64,
/// the tests are skipped, except in CI.
fn aarch64_boot_tests(errors: &mut Vec<String>) -> Result {
    let qemu = "qemu-system-aarch64";
    if Command::new(qemu).arg("--version").stdout(Stdio::null()).status().is_err() {
        if std::env::var_os("CI").is_some() {
            return Err(format!("no {qemu} for the arm64 boot tests, install qemu-system-arm"));
        }
        println!("boot tests on arm64: skipped, no {qemu}");
        return Ok(());
    }
    cargo(&["build", "--package", "rukernel", "--target", "aarch64-unknown-none"])?;
    let elf_path = workspace_root().join("target/aarch64-unknown-none/debug/rukernel");
    let elf = fs::read(&elf_path).map_err(|e| format!("{}: {e}", elf_path.display()))?;
    let image = elf_path.with_file_name("Image");
    fs::write(&image, arm64_image(&elf)?).map_err(|e| format!("{}: {e}", image.display()))?;
    let initrd = aarch64_initramfs(&elf_path)?;
    let has_busybox = initrd.as_ref().is_some_and(|(_, b)| *b);
    if initrd.is_some() && !has_busybox {
        println!("boot test busybox on arm64: skipped, set RK_BUSYBOX_AARCH64");
    }
    let user_tests: Vec<&str> = match &initrd {
        Some(_) => {
            AARCH64_USER_TESTS.iter().copied().filter(|t| *t != "busybox" || has_busybox).collect()
        }
        None => Vec::new(),
    };
    // The tests run with a GICv3, and the `boot` test also runs with a GICv2. The device tests
    // also run with virtio-pci devices.
    let pci_runs =
        user_tests.iter().filter(|t| matches!(**t, "blk" | "inet")).map(|t| (*t, "3", true));
    let runs = [("boot", "2", false)]
        .into_iter()
        .chain(AARCH64_TESTS.iter().chain(&user_tests).map(|t| (*t, "3", false)))
        .chain(pci_runs);
    // RK_AARCH64_TESTS gives a list of test names with commas, for a run by hand.
    let only = std::env::var("RK_AARCH64_TESTS").ok();
    let selected = |t: &str| only.as_deref().is_none_or(|o| o.split(',').any(|n| n == t));
    for (test, gic, pci) in runs.filter(|(t, _, _)| selected(t)) {
        let test = &test;
        let name = match (gic, pci) {
            ("2", _) => format!("{test} with GICv2"),
            (_, true) => format!("{test} with virtio-pci"),
            _ => String::from(*test),
        };
        let (blk_device, net_device) = if pci {
            ("virtio-blk-pci", "virtio-net-pci")
        } else {
            ("virtio-blk-device", "virtio-net-device")
        };
        let smp = if matches!(*test, "boot" | "smp") { AARCH64_SMP_CPUS } else { "1" };
        // The `inet` test connects to a TCP server on the host, as on x86-64.
        let server = if *test == "inet" { Some(TcpServer::start()?) } else { None };
        let mut cmdline = aarch64_cmdline(test);
        if let Some(server) = &server {
            cmdline = format!("{cmdline} {}", server.port);
        }
        let mut cmd = Command::new(qemu);
        let machine = format!("virt,gic-version={gic}");
        cmd.args(["-M", &machine, "-cpu", "cortex-a72", "-m", "512M", "-smp", smp])
            .args(["-display", "none", "-serial", "stdio", "-monitor", "none", "-no-reboot"])
            // The kernel drives the modern (version 2) virtio-mmio devices only.
            .args(["-global", "virtio-mmio.force-legacy=false"])
            .arg("-kernel")
            .arg(&image)
            .arg("-append")
            .arg(cmdline);
        if let Some((initrd, _)) = initrd.as_ref().filter(|_| user_tests.contains(test)) {
            cmd.arg("-initrd").arg(initrd);
        }
        if *test == "blk" {
            let disk = elf_path.with_file_name("blk.img");
            write_blk_disk(&disk)?;
            cmd.arg("-drive")
                .arg(format!("if=none,id=disk0,format=raw,file={}", disk.display()))
                .arg("-device")
                .arg(format!("{blk_device},drive=disk0"));
        }
        if *test == "inet" {
            cmd.args(["-netdev", "user,id=n0", "-device", &format!("{net_device},netdev=n0")]);
        }
        // PSCI SYSTEM_OFF stops QEMU with the status 0 for a pass and for a failure, so the log
        // gives the result.
        // QEMU emulates each arm64 instruction on an x86-64 host, so init has more time.
        let timeout =
            if user_tests.contains(test) { AARCH64_USER_TIMEOUT } else { BOOT_TEST_TIMEOUT };
        let input = if *test == "busybox" { AARCH64_BUSYBOX_INPUT } else { test_input(test) };
        let (status, log) = run_with_timeout(cmd, timeout, input)?;
        let mut passed = status == Some(0)
            && log.contains("aarch64 booting with linux")
            && log.contains(&format!("smp: {smp} CPUs run"))
            && log.contains(&pass_line(test));
        if *test == "blk" && passed && !blk_disk_has_note(&elf_path.with_file_name("blk.img"))? {
            println!("boot test blk on arm64: the disk image does not have the data of the guest");
            passed = false;
        }
        if passed
            && let Some(server) = server
            && let Err(e) = server.result()
        {
            println!("boot test {name} on arm64: the TCP server on the host: {e}");
            passed = false;
        }
        if passed {
            println!("boot test {name} on arm64: pass");
            if std::env::var_os("RK_BOOT_LOG").is_some() {
                println!("{log}");
            }
        } else {
            let status = status.map_or(String::from("a timeout"), |s| format!("status {s}"));
            errors.push(format!("boot test {name} on arm64: fail with {status}\n{log}"));
        }
    }
    Ok(())
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
