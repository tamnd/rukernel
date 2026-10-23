//! The build checks of rukernel.
//!
//! Each check is a command: `cargo xtask unsafe`, `layers`, `style`, `targets` or `ci`. The CI gate
//! runs the same commands. Thus a check that passes on a developer machine passes in CI.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

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
        "ci" => ci(),
        _ => Err(String::from(
            "usage: cargo xtask <unsafe | layers | style | targets | ci>\n\n\
             unsafe   each crate root forbids unsafe code, except the crates in xtask/unsafe-allowed.txt\n\
             layers   each crate depends only on its layer or a lower layer, per xtask/layers.txt\n\
             style    the prose has no em dashes, no en dashes and no horizontal rules\n\
             targets  the kernel crates build for the three bare metal targets\n\
             ci       all of the above, and fmt, clippy, test and doc",
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

fn ci() -> Result {
    cargo(&["fmt", "--all", "--check"])?;
    check_unsafe()?;
    check_layers()?;
    check_style()?;
    cargo(&["clippy", "--workspace", "--all-targets", "--", "-D", "warnings"])?;
    cargo(&["test", "--workspace", "--no-fail-fast"])?;
    build_targets()?;
    cargo(&["doc", "--workspace", "--no-deps"])?;
    println!("all checks passed");
    Ok(())
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
