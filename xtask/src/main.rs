//! The build checks of rukernel.
//!
//! Each check is a command: `cargo xtask unsafe`, `layers`, `style`, `targets`, `boot-test`, `abi`
//! or `ci`.
//! The CI gate runs the same commands. Thus a check that passes on a developer machine passes in
//! CI. `cargo xtask qemu` boots the kernel for a person to use.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
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
    let allowed: BTreeSet<String> =
        policy("unsafe-allowed.txt")?.into_iter().filter_map(|f| f.into_iter().next()).collect();
    let crates = crates()?;
    let mut errors = Vec::new();
    for c in &crates {
        if allowed.contains(&c.name) {
            continue;
        }
        let text = read(&c.root)?;
        if !text.lines().any(|l| l.trim() == "#![forbid(unsafe_code)]") {
            errors.push(format!(
                "{}: the crate root does not have #![forbid(unsafe_code)]",
                c.root.display()
            ));
        }
    }
    let names: BTreeSet<&str> = crates.iter().map(|c| c.name.as_str()).collect();
    for name in &allowed {
        if !names.contains(name.as_str()) {
            errors.push(format!("xtask/unsafe-allowed.txt: {name} is not a workspace crate"));
        }
    }
    report("unsafe rule", errors)
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
const BOOT_TESTS: &[&str] = &["boot", "trap", "mm", "timer"];

/// Builds the x86-64 kernel and gives the path of the ELF image.
fn build_kernel() -> Result<PathBuf> {
    cargo(&["build", "--package", "rukernel", "--target", "x86_64-unknown-none"])?;
    Ok(workspace_root().join("target/x86_64-unknown-none/debug/rukernel"))
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

fn boot_test() -> Result {
    let kernel = build_kernel()?;
    let mut errors = Vec::new();
    for test in BOOT_TESTS {
        let cmdline = format!("console=ttyS0 rk.test={test}");
        let (status, log) = run_with_timeout(qemu_command(&kernel, &cmdline), BOOT_TEST_TIMEOUT)?;
        let passed = status == Some(QEMU_PASS) && log.contains(&format!("rk.test={test}: pass"));
        if passed {
            println!("boot test {test}: pass");
        } else {
            let status = status.map_or(String::from("a timeout"), |s| format!("status {s}"));
            errors.push(format!("boot test {test}: fail with {status}\n{log}"));
        }
    }
    report("boot tests", errors)
}

/// Runs a command, collects its standard output and stops it after `timeout`. Gives the exit
/// status, or `None` for a timeout.
fn run_with_timeout(mut cmd: Command, timeout: Duration) -> Result<(Option<i32>, String)> {
    let mut child = cmd
        .stdout(Stdio::piped())
        .stdin(Stdio::null())
        .spawn()
        .map_err(|e| format!("cannot run {:?}: {e}", cmd.get_program()))?;
    let mut stdout = child.stdout.take().ok_or("no standard output")?;
    let reader = std::thread::spawn(move || {
        let mut out = Vec::new();
        let _ = stdout.read_to_end(&mut out);
        String::from_utf8_lossy(&out).into_owned()
    });
    let start = Instant::now();
    let status = loop {
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
    let log = reader.join().unwrap_or_default();
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
