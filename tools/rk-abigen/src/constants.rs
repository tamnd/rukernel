//! The uAPI constants, per spec/04-abi-surface.md section 4.3 step 5.
//!
//! The headers do not tell which constants are in one group, so the table `GROUPS` gives each group
//! a header, the name prefixes and a Rust type. For each group the generator asks clang for the
//! macros that the header defines, and keeps the macros with a prefix of the group. Then it
//! compiles a probe for the target. The probe gives each value to an `"i"` asm operand, the same
//! method as asm-offsets in Linux, and the assembly output has the value. A macro that is not an
//! integer constant expression fails a `_Static_assert` in the probe, and the generator drops it.

use crate::{ARCHES, Arch, Output, Result, banner, run_input};
use std::collections::{BTreeMap, HashMap};
use std::fmt::Write;
use std::fs;
use std::path::Path;
use std::process::Command;

/// One group of constants.
struct Group {
    /// The name of the Rust module and of the TOML table.
    module: &'static str,
    /// The header, as user space includes it.
    header: &'static str,
    /// A macro is in the group if its name starts with one of these prefixes.
    prefixes: &'static [&'static str],
    /// The Rust type of the constants. Each value must fit in it.
    ty: &'static str,
    /// The first line of the module documentation.
    doc: &'static str,
}

/// The hand maintained grouping table.
const GROUPS: &[Group] = &[
    Group {
        module: "errno",
        header: "asm/errno.h",
        prefixes: &["E"],
        ty: "u16",
        doc: "The error numbers.",
    },
    Group {
        module: "open",
        header: "linux/fcntl.h",
        prefixes: &["O_"],
        ty: "u32",
        doc: "The flags of `open`.",
    },
    Group {
        module: "fcntl",
        header: "linux/fcntl.h",
        prefixes: &["F_", "FD_"],
        // The special descriptors, for example `FD_PIDFS_ROOT`, are less than zero.
        ty: "i32",
        doc: "The commands and flags of `fcntl`, and the special file descriptors.",
    },
    Group {
        module: "dnotify",
        header: "linux/fcntl.h",
        prefixes: &["DN_"],
        ty: "u32",
        doc: "The events of `F_NOTIFY`.",
    },
    Group {
        module: "at",
        header: "linux/fcntl.h",
        prefixes: &["AT_"],
        ty: "i32",
        doc: "The directory file descriptor and the flags of the `*at` calls.",
    },
    Group {
        module: "mman",
        header: "linux/mman.h",
        prefixes: &["PROT_", "MAP_", "MREMAP_", "MS_", "MCL_", "MADV_", "MLOCK_", "PKEY_"],
        ty: "u32",
        doc: "The flags of `mmap`, `mprotect`, `mremap`, `msync`, `mlock` and `madvise`.",
    },
    Group {
        module: "sched",
        header: "linux/sched.h",
        prefixes: &["CLONE_", "CSIGNAL", "SCHED_"],
        ty: "u64",
        doc: "The flags of `clone` and `clone3`, and the scheduler policies.",
    },
    Group {
        module: "signal",
        header: "asm/signal.h",
        prefixes: &["SIG", "SA_", "SS_", "MINSIGSTKSZ"],
        ty: "u32",
        doc: "The signal numbers and the flags of `sigaction` and `sigaltstack`.",
    },
    Group {
        module: "wait",
        header: "linux/wait.h",
        prefixes: &["W", "P_"],
        ty: "u32",
        doc: "The flags and the ID types of `wait4` and `waitid`.",
    },
    Group {
        module: "futex",
        header: "linux/futex.h",
        prefixes: &["FUTEX_", "FUTEX2_", "ROBUST_LIST_"],
        ty: "u32",
        doc: "The operations and flags of `futex`.",
    },
    Group {
        module: "mount",
        header: "linux/mount.h",
        prefixes: &["MS_", "MNT_"],
        ty: "u32",
        doc: "The flags of `mount` and `umount2`.",
    },
    Group {
        module: "time",
        header: "linux/time.h",
        prefixes: &["CLOCK_", "TIMER_", "ITIMER_"],
        ty: "u32",
        doc: "The clock IDs and the timer flags.",
    },
    Group {
        module: "poll",
        header: "asm/poll.h",
        prefixes: &["POLL"],
        ty: "u32",
        doc: "The events of `poll`.",
    },
    Group {
        module: "stat",
        header: "linux/stat.h",
        prefixes: &["S_I", "STATX_"],
        ty: "u32",
        doc: "The file type and mode bits of `st_mode`, and the masks and attributes of `statx`.",
    },
    Group {
        module: "ioctls",
        header: "asm/ioctls.h",
        prefixes: &["TC", "TIOC", "FIO", "FIONREAD", "FIONBIO"],
        ty: "u32",
        doc: "The generic `ioctl` commands of terminals and files.",
    },
    Group {
        module: "termbits",
        header: "asm/termbits.h",
        prefixes: &[""],
        ty: "u32",
        doc: "The flags, the control characters and the speeds of `struct termios`.",
    },
    Group {
        module: "auxv",
        header: "linux/auxvec.h",
        prefixes: &["AT_"],
        ty: "u32",
        doc: "The types of the entries of the auxiliary vector.",
    },
    Group {
        module: "elf",
        header: "linux/elf.h",
        prefixes: &["ET_", "PT_", "PF_", "EM_", "ELFCLASS", "ELFDATA", "EV_", "EI_", "ELFOSABI_"],
        ty: "u32",
        doc: "The values of the ELF header and the program header.",
    },
    Group {
        module: "random",
        header: "linux/random.h",
        prefixes: &["GRND_"],
        ty: "u32",
        doc: "The flags of `getrandom`.",
    },
];

/// The probe gives up after this many tries. Each try drops the macros that failed.
const PROBE_TRIES: usize = 8;

/// One constant of one architecture.
#[derive(Clone, PartialEq, Eq)]
struct Constant {
    name: String,
    value: i128,
    /// The other constant of the group that the macro names, if the macro is an alias.
    alias: Option<String>,
}

/// A clang command for the target, with the installed headers. scripts/headers_install.sh
/// defines `__EXPORTED_HEADERS__`, so the generator defines it too.
pub(crate) fn clang(arch: &Arch, sysroot: &Path) -> Command {
    let mut cmd = Command::new("clang");
    cmd.arg(format!("--target={}", arch.triple))
        .arg("-D__EXPORTED_HEADERS__")
        .args(["-std=gnu11", "-ffreestanding", "-nostdlibinc", "-x", "c", "-"])
        .arg("-I")
        .arg(sysroot.join("include"));
    cmd
}

/// Gives the object-like macros that `header` defines, with their definitions.
fn macros(arch: &Arch, sysroot: &Path, header: &str) -> Result<BTreeMap<String, String>> {
    let (ok, out, err) =
        run_input(clang(arch, sysroot).args(["-E", "-dM"]), &format!("#include <{header}>\n"))?;
    if !ok {
        return Err(format!("{header} for {}: {err}", arch.name));
    }
    let mut macros = BTreeMap::new();
    for line in out.lines() {
        let Some(rest) = line.strip_prefix("#define ") else { continue };
        let (name, body) = rest.split_once(' ').unwrap_or((rest, ""));
        // A function-like macro has `(` in its name.
        if name.starts_with(|c: char| c.is_ascii_uppercase())
            && name.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
        {
            macros.insert(name.to_string(), body.trim().to_string());
        }
    }
    Ok(macros)
}

/// Compiles the probe for `names` and gives the value of each name that is an integer constant.
fn probe(
    arch: &Arch,
    sysroot: &Path,
    header: &str,
    names: &[&str],
) -> Result<BTreeMap<String, i128>> {
    let mut names: Vec<&str> = names.to_vec();
    for _ in 0..PROBE_TRIES {
        // Line 1 is the include and line 2 opens the function, so name `i` is on line `i + 3`.
        let mut src = format!("#include <{header}>\nvoid rk_probe(void) {{\n");
        for name in &names {
            let _ = writeln!(
                src,
                "_Static_assert(({name}) || 1, \"\"); __asm__ volatile(\"\\n.ascii \\\"->{name} %0 %1\\\"\" :: \"i\"((long long)({name})), \"i\"(({name}) < 0));"
            );
        }
        src.push_str("}\n");
        let (ok, out, err) = run_input(
            clang(arch, sysroot).args([
                "-S",
                "-o",
                "-",
                "-ferror-limit=0",
                "-fno-caret-diagnostics",
                "-Werror=gnu-folding-constant",
            ]),
            &src,
        )?;
        if ok {
            return parse_probe(&out);
        }
        // Drop each name with an error on its line, and try again.
        let mut bad = Vec::new();
        for line in err.lines().filter(|l| l.contains(": error:")) {
            let n = line
                .strip_prefix("<stdin>:")
                .and_then(|r| r.split(':').next())
                .and_then(|n| n.parse::<usize>().ok())
                .and_then(|n| n.checked_sub(3))
                .filter(|n| *n < names.len());
            match n {
                Some(n) => bad.push(n),
                None => return Err(format!("probe of {header} for {}: {line}", arch.name)),
            }
        }
        if bad.is_empty() {
            return Err(format!("probe of {header} for {}: {err}", arch.name));
        }
        names =
            names.iter().enumerate().filter(|(i, _)| !bad.contains(i)).map(|(_, n)| *n).collect();
    }
    Err(format!("probe of {header} for {}: too many tries", arch.name))
}

/// Reads the lines `->NAME VALUE NEGATIVE` of the probe. The assembler syntax of x86-64 puts `$`
/// before an immediate. The value is printed as a signed 64 bit number, and NEGATIVE tells if the
/// value of the C expression is less than zero.
fn parse_probe(asm: &str) -> Result<BTreeMap<String, i128>> {
    let mut values = BTreeMap::new();
    for line in asm.lines() {
        let Some(rest) = line
            .trim()
            .strip_prefix(".ascii\t\"->")
            .or_else(|| line.trim().strip_prefix(".ascii \"->"))
        else {
            continue;
        };
        let rest = rest.trim_end_matches('"');
        let f: Vec<&str> = rest.split(' ').map(|s| s.trim_start_matches(['$', '#'])).collect();
        let bad = || format!("bad probe line: {line}");
        let [name, value, negative] = f[..] else { return Err(bad()) };
        let value: i64 = value.parse().map_err(|_| bad())?;
        let value = if negative == "1" { i128::from(value) } else { i128::from(value as u64) };
        values.insert(name.to_string(), value);
    }
    Ok(values)
}

/// The range of a Rust integer type.
fn range(ty: &str) -> Result<(i128, i128)> {
    Ok(match ty {
        "u16" => (0, i128::from(u16::MAX)),
        "u32" => (0, i128::from(u32::MAX)),
        "u64" => (0, i128::from(u64::MAX)),
        "i32" => (i128::from(i32::MIN), i128::from(i32::MAX)),
        _ => return Err(format!("no range for type {ty}")),
    })
}

/// Reads the comment after each `#define` in the headers, for the documentation. A multi line
/// comment is not read.
fn comments(dir: &Path, out: &mut HashMap<String, String>) -> Result {
    let mut entries: Vec<_> = fs::read_dir(dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            comments(&path, out)?;
            continue;
        }
        let text = fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        for line in text.lines() {
            let Some(rest) = line.trim_start().strip_prefix('#') else { continue };
            let Some(rest) = rest.trim_start().strip_prefix("define") else { continue };
            let rest = rest.trim_start();
            let name: String =
                rest.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').collect();
            let Some(start) = rest.find("/*") else { continue };
            let Some(text) = rest[start + 2..].strip_suffix("*/") else { continue };
            let text = text.trim().trim_start_matches(['*', ' ']);
            if !text.is_empty() && !text.contains("*/") {
                out.entry(name).or_insert_with(|| text.to_string());
            }
        }
    }
    Ok(())
}

/// Makes a line of documentation from a header comment. Markdown must not read a link or a tag in
/// it.
fn doc_line(text: &str) -> String {
    let mut s = String::new();
    for c in text.chars() {
        if matches!(c, '[' | ']' | '<' | '>' | '`' | '*' | '_' | '\\') {
            s.push('\\');
        }
        s.push(c);
    }
    let mut chars = s.chars();
    let mut s = match chars.next() {
        Some(c) => c.to_uppercase().chain(chars).collect(),
        None => s,
    };
    if !s.ends_with(['.', '?', '!']) {
        s.push('.');
    }
    s
}

pub(crate) fn generate(tree: &Path, sysroot_dir: &Path, out: &mut Output) -> Result {
    // The errno values of each architecture, to check that they are the same.
    let mut errnos: Vec<(&str, Vec<Constant>, HashMap<String, String>)> = Vec::new();
    for arch in ARCHES {
        let mut docs = HashMap::new();
        let sysroot = sysroot_dir.join(arch.name);
        crate::sysroot::build(tree, arch.linux, &sysroot)?;
        // The headers of the architecture first, so its comments win.
        comments(&sysroot.join("include/asm"), &mut docs)?;
        comments(&sysroot.join("include"), &mut docs)?;
        let mut toml = banner("#", "from the uAPI headers");
        let _ = writeln!(
            toml,
            "#\n# The integer constants of each group in rk-abigen/src/constants.rs."
        );
        for group in GROUPS {
            let all = macros(arch, &sysroot, group.header)?;
            let names: Vec<&str> = all
                .keys()
                .map(String::as_str)
                .filter(|n| group.prefixes.iter().any(|p| n.starts_with(p)))
                .collect();
            let values = probe(arch, &sysroot, group.header, &names)?;
            let (min, max) = range(group.ty)?;
            let mut constants = Vec::new();
            for (name, value) in &values {
                // A mask such as `~FUTEX_PRIVATE_FLAG` is a negative `int` in C. For an unsigned
                // type the value is converted as a C cast to that type converts it.
                let value = &if min == 0 && *value < 0 && *value >= -(max / 2 + 1) {
                    value + max + 1
                } else {
                    *value
                };
                if *value < min || *value > max {
                    return Err(format!(
                        "{} for {}: {name} is {value}, which is not a {}",
                        group.header, arch.name, group.ty
                    ));
                }
                let body = &all[name];
                let alias = values.contains_key(body).then(|| body.clone());
                constants.push(Constant { name: name.clone(), value: *value, alias });
            }
            constants.sort_by(|a, b| (a.value, &a.name).cmp(&(b.value, &b.name)));
            let _ = writeln!(toml, "\n[{}]\nheader = \"{}\"", group.module, group.header);
            for c in &constants {
                let _ = writeln!(toml, "{} = {}", c.name, c.value);
            }
            out.module(arch.name, group.module, rust(group, &constants, &docs));
            if group.module == "errno" {
                errnos.push((arch.name, constants, docs.clone()));
            }
        }
        out.abi(&format!("{}/constants.toml", arch.name), toml);
    }
    let Some((first, errno, docs)) = errnos.first() else { return Ok(()) };
    if let Some((other, _, _)) = errnos.iter().find(|(_, e, _)| e != errno) {
        return Err(format!("the errno values of {first} and {other} are not the same"));
    }
    out.common("errno", errno_impl(errno, docs));
    Ok(())
}

/// Gives a Rust literal. A value of 256 or more is in hex, because most of these values are flags
/// or masks. Each group of four hex digits has a `_` before it.
fn literal(value: i128) -> String {
    if !(256..).contains(&value) {
        return value.to_string();
    }
    let hex = format!("{value:x}");
    let mut s = String::from("0x");
    for (i, c) in hex.chars().enumerate() {
        if i > 0 && (hex.len() - i) % 4 == 0 {
            s.push('_');
        }
        s.push(c);
    }
    s
}

fn doc(c: &Constant, header: &str, docs: &HashMap<String, String>) -> String {
    match (docs.get(&c.name), &c.alias) {
        (Some(text), _) => format!("/// {}", doc_line(text)),
        (None, Some(alias)) => format!("/// The same value as `{alias}`."),
        (None, None) => format!("/// `{}` from `<{header}>`.", c.name),
    }
}

fn rust(group: &Group, constants: &[Constant], docs: &HashMap<String, String>) -> String {
    let mut s = banner("//", &format!("from <{}>", group.header));
    let _ = writeln!(s, "\n//! {}\n", group.doc);
    for c in constants {
        let _ = writeln!(
            s,
            "{}\npub const {}: {} = {};",
            doc(c, group.header, docs),
            c.name,
            group.ty,
            literal(c.value)
        );
    }
    s
}

/// The constants of `Errno`. The errno values are the same on each architecture of rukernel, so
/// the type has one set.
fn errno_impl(errno: &[Constant], docs: &HashMap<String, String>) -> String {
    let mut s = banner("//", "from <asm/errno.h>");
    let _ = writeln!(
        s,
        "\n//! The error numbers as `Errno` values. They are the same on each architecture.\n\n\
         impl crate::Errno {{"
    );
    for c in errno {
        let _ = writeln!(
            s,
            "{}\npub const {}: Self = Self({});",
            doc(c, "asm/errno.h", docs),
            c.name,
            c.value
        );
    }
    s.push_str("}\n");
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_probe_reads_each_syntax() {
        let asm = "\t.ascii\t\"->EPERM $1 $0\"\n\
                   \t.ascii\t\"->AT_FDCWD -100 1\"\n\
                   \t.ascii\t\"->BIG #-9223372036854775808 #0\"\n";
        let v = parse_probe(asm).unwrap_or_default();
        assert_eq!(v.get("EPERM"), Some(&1));
        assert_eq!(v.get("AT_FDCWD"), Some(&-100));
        assert_eq!(v.get("BIG"), Some(&(1 << 63)));
    }

    #[test]
    fn literal_uses_hex_for_large_values() {
        assert_eq!(literal(-100), "-100");
        assert_eq!(literal(255), "255");
        assert_eq!(literal(0x4000), "0x4000");
        assert_eq!(literal(0x8800_0000), "0x8800_0000");
        assert_eq!(literal(0x2_0000_0000), "0x2_0000_0000");
    }

    #[test]
    fn doc_line_escapes_markdown() {
        assert_eq!(doc_line("no such [file] <dir>"), "No such \\[file\\] \\<dir\\>.");
    }
}
