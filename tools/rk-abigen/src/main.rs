//! The ABI generator of rukernel, per spec/04-abi-surface.md section 4.3.
//!
//! The generator reads a pinned Linux source tree and writes the ABI as data. The output is in the
//! tree, so a build of the kernel never needs a Linux tree, and each change to the ABI is a diff
//! that a person can review.
//!
//! `rk-abigen fetch` downloads the pinned tarball, checks its SHA-256 and unpacks the files that
//! the generator reads. `rk-abigen generate` writes `abi/` and `core/rk-abi/src/generated/`. CI runs both
//! commands and fails if the output is different from the files in the tree.

#![forbid(unsafe_code)]

mod constants;
mod syscalls;
mod sysroot;

use std::collections::BTreeMap;
use std::fmt::Write;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

/// The pinned Linux release, per spec/17-upstream-tracking.md.
const LINUX_VERSION: &str = "7.3";
const TARBALL_URL: &str = "https://cdn.kernel.org/pub/linux/kernel/v7.x/linux-7.3.tar.xz";
/// The SHA-256 of the tarball, from sha256sums.asc on kernel.org.
const TARBALL_SHA256: &str = "87363c24f10e06321eb362765521094e94471f6bff8bce2d6b3e40f39f004953";

/// The files of the Linux tree that the generator reads, other than `sysroot::UAPI_DIRS`. `fetch`
/// unpacks only these.
const TREE_PATHS: &[&str] = &[
    "arch/x86/entry/syscalls/syscall_64.tbl",
    "arch/arm64/kernel/Makefile.syscalls",
    "arch/arm64/tools/syscall_64.tbl",
    "arch/riscv/kernel/Makefile.syscalls",
    "scripts/syscall.tbl",
];

/// An architecture of rukernel.
struct Arch {
    /// The Rust name, as `target_arch` gives it.
    name: &'static str,
    /// The directory under `arch/` in the Linux tree.
    linux: &'static str,
    /// The target triple for clang.
    triple: &'static str,
}

/// The architectures, in the order of their Rust names.
const ARCHES: &[Arch] = &[
    Arch { name: "aarch64", linux: "arm64", triple: "aarch64-linux-gnu" },
    Arch { name: "riscv64", linux: "riscv", triple: "riscv64-linux-gnu" },
    Arch { name: "x86_64", linux: "x86", triple: "x86_64-linux-gnu" },
];

type Result<T = ()> = std::result::Result<T, String>;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("fetch") => fetch(),
        Some("generate") => generate(args.get(1).map(PathBuf::from)),
        _ => Err(String::from(
            "usage: rk-abigen <fetch | generate [TREE]>\n\n\
             fetch     download the pinned Linux tarball, check it and unpack the files to read\n\
             generate  write abi/ and core/rk-abi/src/generated/ from the unpacked tree, or from TREE",
        )),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("rk-abigen: {message}");
            ExitCode::FAILURE
        }
    }
}

/// The directory for the tarball and the unpacked tree. `RK_ABIGEN_CACHE` changes it.
fn cache_dir() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os("RK_ABIGEN_CACHE") {
        return Ok(PathBuf::from(dir));
    }
    let home = std::env::var_os("HOME").ok_or("HOME is not set, set RK_ABIGEN_CACHE")?;
    Ok(PathBuf::from(home).join(".cache/rk-abigen"))
}

fn default_tree() -> Result<PathBuf> {
    Ok(cache_dir()?.join(format!("linux-{LINUX_VERSION}")))
}

fn workspace_root() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest.ancestors().nth(2).map(Path::to_path_buf).unwrap_or(manifest)
}

fn run(cmd: &mut Command) -> Result<String> {
    let out = cmd.output().map_err(|e| format!("{cmd:?}: {e}"))?;
    if !out.status.success() {
        return Err(format!("{cmd:?}: {}\n{}", out.status, String::from_utf8_lossy(&out.stderr)));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Gives the SHA-256 of a file. Linux has `sha256sum` and macOS has `shasum`.
fn sha256(path: &Path) -> Result<String> {
    let out = run(Command::new("sha256sum").arg(path))
        .or_else(|_| run(Command::new("shasum").args(["-a", "256"]).arg(path)))?;
    out.split_whitespace().next().map(String::from).ok_or_else(|| format!("no hash for {path:?}"))
}

fn fetch() -> Result {
    let cache = cache_dir()?;
    fs::create_dir_all(&cache).map_err(|e| format!("{}: {e}", cache.display()))?;
    let tarball = cache.join(format!("linux-{LINUX_VERSION}.tar.xz"));
    if !tarball.exists() || sha256(&tarball)? != TARBALL_SHA256 {
        eprintln!("rk-abigen: downloading {TARBALL_URL}");
        let part = tarball.with_extension("part");
        run(Command::new("curl")
            .args(["--fail", "--location", "--silent", "--show-error"])
            .args(["--retry", "3", "--output"])
            .arg(&part)
            .arg(TARBALL_URL))?;
        let got = sha256(&part)?;
        if got != TARBALL_SHA256 {
            return Err(format!("{TARBALL_URL}: SHA-256 is {got}, want {TARBALL_SHA256}"));
        }
        fs::rename(&part, &tarball).map_err(|e| format!("{}: {e}", tarball.display()))?;
    }
    let tree = default_tree()?;
    if tree.exists() {
        fs::remove_dir_all(&tree).map_err(|e| format!("{}: {e}", tree.display()))?;
    }
    let prefix = format!("linux-{LINUX_VERSION}");
    run(Command::new("tar")
        .arg("-xJf")
        .arg(&tarball)
        .arg("-C")
        .arg(&cache)
        .args(TREE_PATHS.iter().chain(sysroot::UAPI_DIRS).map(|p| format!("{prefix}/{p}"))))?;
    eprintln!("rk-abigen: Linux {LINUX_VERSION} is in {}", tree.display());
    Ok(())
}

fn generate(tree: Option<PathBuf>) -> Result {
    let tree = match tree {
        Some(t) => t,
        None => default_tree()?,
    };
    if !tree.join("scripts/syscall.tbl").exists() {
        return Err(format!("{} has no Linux tree, run `rk-abigen fetch`", tree.display()));
    }
    let root = workspace_root();
    let mut out = Output::new(&root)?;
    syscalls::generate(&tree, &mut out)?;
    constants::generate(&tree, &cache_dir()?.join("sysroot"), &mut out)?;
    out.finish()
}

/// The header of each generated file.
fn banner(comment: &str, source: &str) -> String {
    format!(
        "{comment} rk-abigen generated this file from Linux {LINUX_VERSION}, {source}.\n\
         {comment} Do not edit it. Change rk-abigen and run it again.\n"
    )
}

/// The generated files. `finish` replaces the old output with the new output, so a file that the
/// generator does not write now is removed.
struct Output {
    abi_dir: PathBuf,
    gen_dir: PathBuf,
    files: Vec<(PathBuf, String)>,
    /// The modules of each architecture.
    modules: BTreeMap<&'static str, Vec<&'static str>>,
    /// The modules that are not for one architecture.
    common: Vec<&'static str>,
}

impl Output {
    fn new(root: &Path) -> Result<Self> {
        Ok(Self {
            abi_dir: root.join("abi").join(LINUX_VERSION),
            gen_dir: root.join("core/rk-abi/src/generated"),
            files: Vec::new(),
            modules: BTreeMap::new(),
            common: Vec::new(),
        })
    }

    /// Adds a file under `abi/<version>/`.
    fn abi(&mut self, path: &str, text: String) {
        self.files.push((self.abi_dir.join(path), text));
    }

    /// Adds a file under `core/rk-abi/src/generated/`.
    fn rust(&mut self, path: &str, text: String) {
        self.files.push((self.gen_dir.join(path), text));
    }

    /// Adds the module `module` of the architecture `arch`.
    fn module(&mut self, arch: &'static str, module: &'static str, text: String) {
        self.rust(&format!("{arch}/{module}.rs"), text);
        self.modules.entry(arch).or_default().push(module);
    }

    /// Adds a module that is not for one architecture. It is private to rk-abi.
    fn common(&mut self, module: &'static str, text: String) {
        self.rust(&format!("{module}.rs"), text);
        self.common.push(module);
    }

    fn finish(mut self) -> Result {
        // rustfmt sorts the module declarations, so the generator writes them in that order.
        let mut top = banner("//", "with the modules of each architecture");
        top.push_str("\n//! The generated ABI of each architecture.\n\n");
        for (arch, mut modules) in std::mem::take(&mut self.modules) {
            modules.sort_unstable();
            let mut text = banner("//", "with the modules of this architecture");
            let _ = writeln!(text, "\n//! The ABI of {arch}.\n");
            for m in modules {
                let _ = writeln!(text, "pub mod {m};");
            }
            self.rust(&format!("{arch}/mod.rs"), text);
            let _ = writeln!(top, "pub mod {arch};");
        }
        let mut common = std::mem::take(&mut self.common);
        common.sort_unstable();
        for m in common {
            let _ = writeln!(top, "mod {m};");
        }
        self.rust("mod.rs", top);

        for dir in [&self.abi_dir, &self.gen_dir] {
            if dir.exists() {
                fs::remove_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
            }
        }
        for (path, text) in &self.files {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
            }
            fs::write(path, text).map_err(|e| format!("{}: {e}", path.display()))?;
        }
        // rustfmt aligns the trailing comments of the tables. The toolchain is pinned in
        // rust-toolchain.toml, so the output is the same on each machine.
        let rust: Vec<&PathBuf> = self
            .files
            .iter()
            .map(|(p, _)| p)
            .filter(|p| p.extension().is_some_and(|e| e == "rs"))
            .collect();
        if !rust.is_empty() {
            run(Command::new("rustfmt").args(["--edition", "2024"]).args(rust))?;
        }
        eprintln!("rk-abigen: wrote {} files", self.files.len());
        Ok(())
    }
}
