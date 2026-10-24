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
             boot-test  boot the x86-64 kernel in QEMU and check the self tests, or only the named tests\n\
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
    "busybox",
    "ltp",
    "alpine",
    "debian",
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

/// The applets that the `busybox` boot test uses. Each one is a link to /bin/busybox.
const BUSYBOX_APPLETS: &[&str] = &[
    "sh", "echo", "tr", "sleep", "cat", "wc", "ls", "test", "mkdir", "rm", "true", "false", "mount",
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
echo \"alpine: release $(cat /etc/alpine-release)\"
ls -l /lib/ld-musl-x86_64.so.1
/lib/ld-musl-x86_64.so.1 --list /bin/busybox
apk --version
apk info --no-network | grep -q musl
echo one two | tr a-z A-Z | grep -q 'ONE TWO'
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
        // `cp -R` keeps the symbolic links of the tree.
        let status = Command::new("cp")
            .arg("-pR")
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
    cargo(&["build", "--package", "rukernel", "--target", "x86_64-unknown-none"])?;
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
    qemu_command_with(kernel, &kernel.with_file_name("initramfs.cpio"), cmdline)
}

/// The QEMU command for the x86-64 kernel with the initramfs `initrd`.
fn qemu_command_with(kernel: &Path, initrd: &Path, cmdline: &str) -> Command {
    let mut cmd = Command::new("qemu-system-x86_64");
    cmd.args(["-machine", "q35", "-m", "512M", "-smp", "1", "-display", "none"])
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
        "init" | "tty" => kernel.with_file_name("user-init").exists(),
        "busybox" => kernel.with_file_name("busybox-ready").exists(),
        "ltp" => kernel.with_file_name("initramfs-ltp.cpio").exists(),
        t if ROOTFS.iter().any(|r| r.name == t) => rootfs_initramfs(kernel, t).exists(),
        _ => true,
    }
}

/// The command line of a boot test. The `tty` test runs init with the argument `tty`, which is
/// after `--`, as Linux gives the arguments of init.
fn test_cmdline(test: &str) -> String {
    match test {
        "tty" => String::from("console=ttyS0 rk.test=init -- tty"),
        "busybox" => String::from("console=ttyS0 rk.test=init rdinit=/bin/sh -- -i"),
        "ltp" => String::from("console=ttyS0 rk.test=init rdinit=/ltp/run"),
        t if ROOTFS.iter().any(|r| r.name == t) => {
            String::from("console=ttyS0 rk.test=init rdinit=/init")
        }
        _ => format!("console=ttyS0 rk.test={test}"),
    }
}

/// The line that the kernel prints when the boot test `test` passes.
fn pass_line(test: &str) -> String {
    let test = if matches!(test, "tty" | "busybox" | "ltp") || ROOTFS.iter().any(|r| r.name == test)
    {
        "init"
    } else {
        test
    };
    format!("rk.test={test}: pass")
}

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
        _ => &[],
    }
}

fn boot_test(names: &[String]) -> Result {
    if let Some(name) = names.iter().find(|n| !BOOT_TESTS.contains(&n.as_str())) {
        return Err(format!("{name}: no such boot test"));
    }
    let kernel = build_kernel()?;
    let mut errors = Vec::new();
    let named = |t: &&&str| names.is_empty() || names.iter().any(|n| n == **t);
    for test in BOOT_TESTS.iter().filter(named).filter(|t| can_run(&kernel, t)) {
        let (cmd, timeout) = if *test == "ltp" {
            let initrd = kernel.with_file_name("initramfs-ltp.cpio");
            (qemu_command_with(&kernel, &initrd, &test_cmdline(test)), LTP_TIMEOUT)
        } else if ROOTFS.iter().any(|r| r.name == *test) {
            let initrd = rootfs_initramfs(&kernel, test);
            (qemu_command_with(&kernel, &initrd, &test_cmdline(test)), BOOT_TEST_TIMEOUT)
        } else {
            (qemu_command(&kernel, &test_cmdline(test)), BOOT_TEST_TIMEOUT)
        };
        let (status, log) = run_with_timeout(cmd, timeout, test_input(test))?;
        let passed = status == Some(QEMU_PASS) && log.contains(&pass_line(test));
        if passed {
            println!("boot test {test}: pass");
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
