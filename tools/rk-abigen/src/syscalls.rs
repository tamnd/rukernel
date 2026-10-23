//! The system call tables, per spec/04-abi-surface.md section 4.3 step 2.
//!
//! Each line of a Linux syscall table is `NR ABI NAME [ENTRY [COMPAT [noreturn]]]`. An
//! architecture uses the lines whose ABI is in its ABI list. The Linux build makes the list from
//! the defaults in scripts/Makefile.asm-headers and from the arch Makefile.syscalls. This module
//! reads the same files, so a change upstream is a change in the output.

use crate::{Output, Result, banner};
use std::fmt::Write;
use std::fs;
use std::path::Path;

/// One line of a syscall table.
struct Entry {
    nr: u32,
    abi: String,
    name: String,
    entry: Option<String>,
    compat: Option<String>,
    noreturn: bool,
}

/// The table of one architecture.
struct Arch {
    /// The Rust name of the architecture, as `target_arch` gives it.
    name: &'static str,
    /// The path of the table in the Linux tree.
    table: String,
    /// The ABIs of the native 64 bit table.
    native: Vec<String>,
    /// More ABIs for the TOML file only. The native table does not use them.
    other: Vec<&'static str>,
}

/// The default ABIs and table for an architecture that uses the generic table, per
/// scripts/Makefile.asm-headers.
const GENERIC_ABIS: &[&str] = &["common", "64"];
const GENERIC_TABLE: &str = "scripts/syscall.tbl";

fn read(tree: &Path, path: &str) -> Result<String> {
    fs::read_to_string(tree.join(path)).map_err(|e| format!("{path}: {e}"))
}

/// Reads `syscall_abis_64` and `syscalltbl` from an arch Makefile.syscalls.
fn generic_arch(tree: &Path, name: &'static str, makefile: &str) -> Result<Arch> {
    let text = read(tree, makefile)?;
    let mut native: Vec<String> = GENERIC_ABIS.iter().map(|s| s.to_string()).collect();
    let mut table = GENERIC_TABLE.to_string();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("syscall_abis_64") {
            let rest = rest.trim_start().strip_prefix("+=").ok_or_else(|| {
                format!("{makefile}: only += is known for syscall_abis_64: {line}")
            })?;
            native.extend(rest.split_whitespace().map(String::from));
        } else if let Some(rest) = line.strip_prefix("syscalltbl") {
            let path = rest.trim_start().trim_start_matches([':', '=']).trim();
            table = path.replace("%", "64");
        }
    }
    Ok(Arch { name, table, native, other: Vec::new() })
}

fn arches(tree: &Path) -> Result<Vec<Arch>> {
    Ok(vec![
        // arch/x86/entry/syscalls/Makefile: unistd_64.h uses common,64 and unistd_x32.h uses
        // common,x32. Only the 64 bit table is native in R0. The x32 lines go in the TOML file.
        Arch {
            name: "x86_64",
            table: "arch/x86/entry/syscalls/syscall_64.tbl".into(),
            native: vec!["common".into(), "64".into()],
            other: vec!["x32"],
        },
        generic_arch(tree, "aarch64", "arch/arm64/kernel/Makefile.syscalls")?,
        generic_arch(tree, "riscv64", "arch/riscv/kernel/Makefile.syscalls")?,
    ])
}

fn parse(path: &str, text: &str) -> Result<Vec<Entry>> {
    let mut entries = Vec::new();
    for (n, line) in text.lines().enumerate() {
        if !line.starts_with(|c: char| c.is_ascii_digit()) {
            continue;
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        let bad = || format!("{path}:{}: bad line: {line}", n + 1);
        if f.len() < 3 || f.len() > 6 {
            return Err(bad());
        }
        let opt = |i: usize| f.get(i).filter(|s| **s != "-").map(|s| s.to_string());
        let noreturn = match f.get(5) {
            None => false,
            Some(&"noreturn") => true,
            Some(_) => return Err(bad()),
        };
        entries.push(Entry {
            nr: f[0].parse().map_err(|_| bad())?,
            abi: f[1].to_string(),
            name: f[2].to_string(),
            entry: opt(3),
            compat: opt(4),
            noreturn,
        });
    }
    Ok(entries)
}

/// A TOML string. The names in the tables are identifiers, but the generator does not depend on
/// that.
fn toml_str(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

pub(crate) fn generate(tree: &Path, out: &mut Output) -> Result {
    let mut arches = arches(tree)?;
    // rustfmt sorts the module declarations, so the generator writes them in that order.
    arches.sort_by_key(|a| a.name);
    let mut generated_mod = banner("//", "with the modules of each architecture");
    generated_mod.push_str("\n//! The generated ABI of each architecture.\n\n");
    for arch in &arches {
        let entries = parse(&arch.table, &read(tree, &arch.table)?)?;
        let native: Vec<&Entry> = entries.iter().filter(|e| arch.native.contains(&e.abi)).collect();
        // scripts/syscalltbl.sh rejects a table that is not sorted or has a number two times.
        for w in native.windows(2) {
            if w[0].nr >= w[1].nr {
                return Err(format!(
                    "{}: number {} is not in order or is two times",
                    arch.table, w[1].nr
                ));
            }
        }
        out.abi(&format!("{}/syscalls.toml", arch.name), toml(arch, &entries));
        out.rust(&format!("{}/syscalls.rs", arch.name), rust(arch, &native));
        out.rust(
            &format!("{}/mod.rs", arch.name),
            format!(
                "{}\n//! The ABI of {}.\n\npub mod syscalls;\n",
                banner("//", "with the modules of this architecture"),
                arch.name
            ),
        );
        let _ = writeln!(generated_mod, "pub mod {};", arch.name);
    }
    out.rust("mod.rs", generated_mod);
    Ok(())
}

fn toml(arch: &Arch, entries: &[Entry]) -> String {
    let mut s = banner("#", &format!("from {}", arch.table));
    let _ = writeln!(s, "#\n# One entry for each line of the table with one of the ABIs below.");
    let _ = writeln!(s, "# The native 64 bit table uses the ABIs in `native`.\n");
    let abis = |v: &mut dyn Iterator<Item = &str>| v.map(toml_str).collect::<Vec<_>>().join(", ");
    let _ = writeln!(s, "native = [{}]", abis(&mut arch.native.iter().map(String::as_str)));
    let _ = writeln!(s, "other = [{}]", abis(&mut arch.other.iter().copied()));
    for e in entries {
        if !arch.native.contains(&e.abi) && !arch.other.contains(&e.abi.as_str()) {
            continue;
        }
        let _ = writeln!(
            s,
            "\n[[syscall]]\nnr = {}\nabi = {}\nname = {}",
            e.nr,
            toml_str(&e.abi),
            toml_str(&e.name)
        );
        if let Some(entry) = &e.entry {
            let _ = writeln!(s, "entry = {}", toml_str(entry));
        }
        if let Some(compat) = &e.compat {
            let _ = writeln!(s, "compat = {}", toml_str(compat));
        }
        if e.noreturn {
            let _ = writeln!(s, "noreturn = true");
        }
    }
    s
}

fn rust(arch: &Arch, native: &[&Entry]) -> String {
    let count = native.last().map_or(0, |e| e.nr + 1);
    let mut s = banner("//", &format!("from {}", arch.table));
    let _ = writeln!(
        s,
        "\n//! The system call numbers of {} in Linux.\n//!\n//! The table uses the lines of the ABIs {}.",
        arch.name,
        arch.native.join(", ")
    );
    let _ = writeln!(
        s,
        "\n/// The highest system call number plus one.\npub const NR_SYSCALLS: usize = {count};"
    );
    for e in native {
        let doc = if e.entry.is_some() {
            format!("/// The number of `{}`.", e.name)
        } else {
            format!("/// The number of `{}`. Linux has no entry point for this number.", e.name)
        };
        let _ = writeln!(s, "{doc}\npub const {}: u32 = {};", e.name.to_ascii_uppercase(), e.nr);
    }
    let _ = writeln!(
        s,
        "\n/// The name of each system call number. A number with no entry point in Linux is `None`.\n\
         pub static SYSCALLS: [Option<&str>; NR_SYSCALLS] = ["
    );
    let mut next = 0;
    for e in native {
        while next < e.nr {
            let _ = writeln!(s, "    None, // {next}");
            next += 1;
        }
        match &e.entry {
            Some(_) => {
                let _ = writeln!(s, "    Some({}), // {}", toml_str(&e.name), e.nr);
            }
            None => {
                let _ = writeln!(s, "    None, // {}", e.nr);
            }
        }
        next += 1;
    }
    s.push_str("];\n");
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_reads_each_column() {
        let text = "# a comment\n\
                    0\tcommon\tread\tsys_read\n\
                    60\tcommon\texit\tsys_exit\t-\tnoreturn\n\
                    134\t64\tuselib\n\
                    512\tx32\trt_sigaction\tcompat_sys_rt_sigaction\n";
        let e = parse("t.tbl", text).unwrap_or_default();
        assert_eq!(e.len(), 4);
        assert_eq!(
            (e[0].nr, e[0].name.as_str(), e[0].entry.as_deref()),
            (0, "read", Some("sys_read"))
        );
        assert!(e[1].noreturn && e[1].compat.is_none());
        assert!(e[2].entry.is_none());
        assert_eq!(e[3].abi, "x32");
    }

    #[test]
    fn parse_rejects_a_bad_last_column() {
        assert!(parse("t.tbl", "1\tcommon\twrite\tsys_write\t-\tnever\n").is_err());
    }
}
