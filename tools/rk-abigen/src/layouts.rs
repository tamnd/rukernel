//! The structure layouts, per spec/04-abi-surface.md section 4.3 step 4.
//!
//! clang compiles one file that takes the size of each structure in `STRUCTS`, with
//! `-fdump-record-layouts-canonical`. The dump gives the offset, the canonical C type and the name
//! of each field, and the size and the alignment of each structure. The generator writes a
//! `#[repr(C)]` Rust structure with the same layout, and a compile time check of each offset and
//! of the size.
//!
//! The Rust structure has a padding field for each gap, so that it has no padding bytes and can
//! derive the zerocopy traits. A structure with a smaller alignment than its fields, for example
//! `struct epoll_event` on x86-64, is `packed`.

use crate::{ARCHES, Arch, Output, Result, banner, run_input};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;
use std::path::Path;

/// The structures of each header. A structure that one of these has as a field is also generated.
const STRUCTS: &[(&str, &[&str])] = &[
    ("asm/stat.h", &["stat"]),
    ("asm/statfs.h", &["statfs"]),
    ("linux/stat.h", &["statx"]),
    (
        "linux/time_types.h",
        &[
            "__kernel_timespec",
            "__kernel_itimerspec",
            "__kernel_old_timeval",
            "__kernel_old_itimerval",
        ],
    ),
    ("linux/timex.h", &["__kernel_timex"]),
    ("linux/uio.h", &["iovec"]),
    ("linux/utsname.h", &["new_utsname"]),
    ("linux/resource.h", &["rlimit", "rlimit64", "rusage"]),
    ("asm/poll.h", &["pollfd"]),
    ("linux/sched.h", &["clone_args"]),
    ("linux/mount.h", &["statmount"]),
    ("linux/fanotify.h", &["fanotify_event_metadata", "fanotify_response"]),
    ("linux/sched/types.h", &["sched_attr"]),
    ("linux/eventpoll.h", &["epoll_event"]),
    ("linux/signalfd.h", &["signalfd_siginfo"]),
    ("linux/futex.h", &["robust_list", "robust_list_head", "futex_waitv"]),
    ("linux/openat2.h", &["open_how"]),
    ("linux/sysinfo.h", &["sysinfo"]),
    ("asm/signal.h", &["sigaltstack"]),
    ("linux/capability.h", &["__user_cap_header_struct", "__user_cap_data_struct"]),
    ("asm/termbits.h", &["termios", "termios2"]),
    ("asm/termios.h", &["winsize"]),
];

/// The type of one field.
#[derive(Clone, PartialEq, Eq)]
enum Type {
    /// A Rust integer type.
    Int(&'static str),
    /// A structure, by its tag or by the name of its typedef.
    Struct(String),
    /// An array with the length of each dimension, outer first.
    Array(Box<Type>, Vec<usize>),
}

struct Field {
    name: String,
    ty: Type,
    offset: usize,
}

struct Layout {
    /// The C name: `struct stat`, or the name of the typedef of an anonymous structure.
    c_name: String,
    fields: Vec<Field>,
    size: usize,
    align: usize,
}

/// Gives the Rust type of a canonical C type. A pointer is a user address, and each architecture
/// of rukernel has 64 bit pointers. `char` is `u8`, because its sign is not the same on each
/// architecture and the uAPI uses it for bytes.
fn scalar(c: &str) -> Option<&'static str> {
    Some(match c {
        "char" | "unsigned char" => "u8",
        "signed char" => "i8",
        "short" => "i16",
        "unsigned short" => "u16",
        "int" => "i32",
        "unsigned int" => "u32",
        "long" | "long long" => "i64",
        "unsigned long" | "unsigned long long" => "u64",
        _ => return None,
    })
}

fn parse_type(c: &str) -> Result<Type> {
    // A pointer to a function or to an array, for example `void (*)(int)`.
    if c.contains("(*") {
        return Ok(Type::Int("u64"));
    }
    if c.ends_with(']')
        && let Some(i) = c.find('[')
    {
        let base = parse_type(c[..i].trim())?;
        // A flexible array member, for example `char str[]` at the end of `struct statmount`,
        // has no size. It is an array of 0 elements in Rust.
        let dims = c[i..]
            .split(']')
            .filter(|s| !s.is_empty())
            .map(|s| match s.trim_start_matches('[') {
                "" => Ok(0),
                n => n.parse::<usize>(),
            })
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| format!("bad array type {c}"))?;
        return Ok(Type::Array(Box::new(base), dims));
    }
    if c.ends_with('*') {
        return Ok(Type::Int("u64"));
    }
    if let Some(name) = c.strip_prefix("struct ") {
        if name.contains(' ') {
            return Err(format!("an anonymous structure is not supported: {c}"));
        }
        return Ok(Type::Struct(name.to_string()));
    }
    if let Some(t) = scalar(c) {
        return Ok(Type::Int(t));
    }
    // The typedef of an anonymous structure, for example `__kernel_fsid_t`. The layout dump has
    // the structure under this name.
    if c.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '_') {
        return Ok(Type::Struct(c.to_string()));
    }
    Err(format!("no Rust type for {c}"))
}

/// Reads the output of `-fdump-record-layouts-canonical`.
fn parse_dump(text: &str) -> Result<BTreeMap<String, Layout>> {
    let mut layouts = BTreeMap::new();
    for block in text.split("*** Dumping AST Record Layout").skip(1) {
        let mut lines = block.lines().filter(|l| l.contains('|'));
        let Some(head) = lines.next() else { continue };
        let Some((_, decl)) = head.split_once("| ") else { continue };
        let c_name = decl.trim();
        // A union is not generated now. The generator stops if a structure uses one.
        if c_name.starts_with("union ") {
            continue;
        }
        let name = c_name.strip_prefix("struct ").unwrap_or(c_name);
        let mut fields = Vec::new();
        let mut size_align = None;
        for line in lines {
            let (offset, rest) = line.split_once('|').unwrap_or_default();
            let rest = rest.strip_prefix(' ').unwrap_or(rest);
            if let Some(info) = rest.trim().strip_prefix('[') {
                let get = |key: &str| {
                    info.split([',', ']'])
                        .find_map(|kv| kv.trim().strip_prefix(key)?.parse::<usize>().ok())
                };
                size_align = get("sizeof=").zip(get("align="));
                continue;
            }
            let depth = rest.len() - rest.trim_start().len();
            if depth != 2 {
                continue;
            }
            let bad = || format!("struct {name}: bad layout line: {line}");
            // An unnamed bit field, for example `int :32;` at the end of `struct timex`, only
            // reserves space. The gap gets a padding field as each other gap does.
            if offset.contains(':') && !rest.trim().contains(' ') {
                continue;
            }
            if offset.contains(':') {
                return Err(format!("struct {name}: a bit field is not supported: {line}"));
            }
            let decl = rest.trim();
            let (ty, field) = decl.rsplit_once(' ').ok_or_else(bad)?;
            fields.push(Field {
                name: field.to_string(),
                ty: parse_type(ty).map_err(|e| format!("struct {name}: {e}"))?,
                offset: offset.trim().parse().map_err(|_| bad())?,
            });
        }
        let (size, align) = size_align.ok_or_else(|| format!("struct {name}: no size"))?;
        layouts
            .insert(name.to_string(), Layout { c_name: c_name.to_string(), fields, size, align });
    }
    Ok(layouts)
}

/// The Rust name of a C structure: `__kernel_timespec` is `KernelTimespec`.
fn rust_name(c: &str) -> String {
    c.split('_')
        .filter(|s| !s.is_empty())
        .map(|s| {
            let mut chars = s.chars();
            chars
                .next()
                .map(|f| f.to_ascii_uppercase().to_string() + chars.as_str())
                .unwrap_or_default()
        })
        .collect()
}

/// A field name for Rust. A keyword is a raw identifier.
fn field_name(c: &str) -> String {
    match c {
        "type" | "match" | "mod" | "ref" | "loop" | "move" | "fn" | "impl" | "use" => {
            format!("r#{c}")
        }
        _ => c.to_string(),
    }
}

fn rust_type(ty: &Type) -> String {
    match ty {
        Type::Int(t) => (*t).to_string(),
        Type::Struct(s) => rust_name(s),
        Type::Array(base, dims) => {
            dims.iter().rev().fold(rust_type(base), |inner, n| format!("[{inner}; {n}]"))
        }
    }
}

/// The size and the alignment of a type.
fn size_align(ty: &Type, layouts: &BTreeMap<String, Layout>) -> Result<(usize, usize)> {
    Ok(match ty {
        Type::Int(t) => {
            let n = match *t {
                "u8" | "i8" => 1,
                "u16" | "i16" => 2,
                "u32" | "i32" => 4,
                _ => 8,
            };
            (n, n)
        }
        Type::Struct(s) => {
            let l = layouts.get(s).ok_or_else(|| format!("no layout for struct {s}"))?;
            (l.size, l.align)
        }
        Type::Array(base, dims) => {
            let (size, align) = size_align(base, layouts)?;
            (dims.iter().product::<usize>() * size, align)
        }
    })
}

/// Adds the structures that `name` uses, and then `name`, to `order`.
fn add_with_deps(
    name: &str,
    layouts: &BTreeMap<String, Layout>,
    seen: &mut BTreeSet<String>,
    order: &mut Vec<String>,
) -> Result {
    if !seen.insert(name.to_string()) {
        return Ok(());
    }
    let layout = layouts.get(name).ok_or_else(|| format!("no layout for struct {name}"))?;
    for f in &layout.fields {
        let mut ty = &f.ty;
        while let Type::Array(base, _) = ty {
            ty = base;
        }
        if let Type::Struct(s) = ty {
            add_with_deps(s, layouts, seen, order)?;
        }
    }
    order.push(name.to_string());
    Ok(())
}

fn dump(arch: &Arch, sysroot: &Path) -> Result<BTreeMap<String, Layout>> {
    let mut src = String::new();
    for (header, _) in STRUCTS {
        let _ = writeln!(src, "#include <{header}>");
    }
    src.push_str("unsigned long rk_sizes[] = {\n");
    for name in STRUCTS.iter().flat_map(|(_, s)| s.iter()) {
        let _ = writeln!(src, "    sizeof(struct {name}),");
    }
    src.push_str("};\n");
    let (ok, out, err) = run_input(
        crate::constants::clang(arch, sysroot).args([
            "-fsyntax-only",
            "-Xclang",
            "-fdump-record-layouts-canonical",
        ]),
        &src,
    )?;
    if !ok {
        return Err(format!("layouts for {}: {err}", arch.name));
    }
    parse_dump(&out)
}

pub(crate) fn generate(sysroot_dir: &Path, out: &mut Output) -> Result {
    for arch in ARCHES {
        let layouts = dump(arch, &sysroot_dir.join(arch.name))?;
        let mut seen = BTreeSet::new();
        let mut order = Vec::new();
        for name in STRUCTS.iter().flat_map(|(_, s)| s.iter()) {
            add_with_deps(name, &layouts, &mut seen, &mut order)?;
        }
        let header_of: BTreeMap<&str, &str> =
            STRUCTS.iter().flat_map(|(h, s)| s.iter().map(move |n| (*n, *h))).collect();
        let mut rust = banner("//", "from the uAPI headers");
        let _ = writeln!(
            rust,
            "\n//! The uAPI structures of {}.\n//!\n//! The field names are the names of Linux. The fields \
             `_padN` are the\n//! padding bytes of the C structure.\n\n\
             #![allow(missing_docs)]\n\n\
             use zerocopy::{{FromBytes, Immutable, IntoBytes, KnownLayout}};",
            arch.name
        );
        let mut toml = banner("#", "from the uAPI headers");
        let _ = writeln!(toml, "#\n# The layout of each structure in rk-abigen/src/layouts.rs.");
        for name in &order {
            let layout = &layouts[name];
            write_struct(&mut rust, name, header_of.get(name.as_str()).copied(), layout, &layouts)
                .map_err(|e| format!("{} struct {name}: {e}", arch.name))?;
            let _ = writeln!(
                toml,
                "\n[[struct]]\nname = \"{name}\"\nsize = {}\nalign = {}",
                layout.size, layout.align
            );
            for f in &layout.fields {
                let _ = writeln!(
                    toml,
                    "[[struct.field]]\nname = \"{}\"\ntype = \"{}\"\noffset = {}",
                    f.name,
                    rust_type(&f.ty),
                    f.offset
                );
            }
        }
        out.module(arch.name, "types", rust);
        out.abi(&format!("{}/types.toml", arch.name), toml);
    }
    Ok(())
}

fn write_struct(
    s: &mut String,
    name: &str,
    header: Option<&str>,
    layout: &Layout,
    layouts: &BTreeMap<String, Layout>,
) -> Result {
    let rust = rust_name(name);
    let mut natural = 1;
    for f in &layout.fields {
        natural = natural.max(size_align(&f.ty, layouts)?.1);
    }
    let repr = if layout.align < natural {
        if layout.align == 1 {
            "C, packed".to_string()
        } else {
            format!("C, packed({})", layout.align)
        }
    } else if layout.align > natural {
        format!("C, align({})", layout.align)
    } else {
        "C".to_string()
    };
    let source = header.map_or_else(String::new, |h| format!(" from `<{h}>`"));
    let _ = writeln!(
        s,
        "\n/// `{}`{source}.\n\
         #[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable)]\n\
         #[repr({repr})]\npub struct {rust} {{",
        layout.c_name
    );
    let mut end = 0;
    let mut pads = 0;
    let mut checks = Vec::new();
    for f in &layout.fields {
        if f.offset < end {
            return Err(format!("field {} overlaps the field before it", f.name));
        }
        if f.offset > end {
            let _ = writeln!(s, "    _pad{pads}: [u8; {}],", f.offset - end);
            pads += 1;
        }
        let name = field_name(&f.name);
        let _ = writeln!(s, "    pub {name}: {},", rust_type(&f.ty));
        checks.push(format!("assert!(core::mem::offset_of!({rust}, {name}) == {});", f.offset));
        end = f.offset + size_align(&f.ty, layouts)?.0;
    }
    if layout.size > end {
        let _ = writeln!(s, "    _pad{pads}: [u8; {}],", layout.size - end);
    }
    s.push_str("}\n\n");
    let _ = writeln!(s, "const _: () = {{\n    assert!(size_of::<{rust}>() == {});", layout.size);
    let _ = writeln!(s, "    assert!(align_of::<{rust}>() == {});", layout.align);
    for c in checks {
        let _ = writeln!(s, "    {c}");
    }
    s.push_str("};\n");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const DUMP: &str = "
*** Dumping AST Record Layout
         0 | struct __kernel_timespec
         0 |   long long tv_sec
         8 |   long long tv_nsec
           | [sizeof=16, align=8]

*** Dumping AST Record Layout
         0 | struct t
         0 |   unsigned int a
         8 |   struct __kernel_timespec ts
         8 |     long long tv_sec
        16 |     long long tv_nsec
        24 |   char[2][3] b
        32 |   struct t * next
        40 |   void (*)(int) handler
           | [sizeof=48, align=8]
";

    #[test]
    fn parse_dump_reads_the_fields() {
        let l = parse_dump(DUMP).unwrap_or_default();
        let t = &l["t"];
        assert_eq!((t.size, t.align, t.fields.len()), (48, 8, 5));
        assert_eq!(rust_type(&t.fields[1].ty), "KernelTimespec");
        assert_eq!(rust_type(&t.fields[2].ty), "[[u8; 3]; 2]");
        assert_eq!(rust_type(&t.fields[3].ty), "u64");
        assert_eq!(t.fields[3].offset, 32);
        assert_eq!(rust_type(&t.fields[4].ty), "u64");
    }

    #[test]
    fn write_struct_adds_padding() {
        let l = parse_dump(DUMP).unwrap_or_default();
        let mut s = String::new();
        assert!(write_struct(&mut s, "t", None, &l["t"], &l).is_ok());
        assert!(s.contains("pub a: u32,\n    _pad0: [u8; 4],\n    pub ts: KernelTimespec,"));
        assert!(s.contains("pub b: [[u8; 3]; 2],\n    _pad1: [u8; 2],"));
    }

    #[test]
    fn names() {
        assert_eq!(rust_name("__kernel_timespec"), "KernelTimespec");
        assert_eq!(rust_name("rlimit64"), "Rlimit64");
        assert_eq!(field_name("type"), "r#type");
    }
}
