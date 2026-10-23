//! The installed uAPI headers of one architecture, per spec/04-abi-surface.md section 4.3 step 1.
//!
//! `make headers_install` needs the Linux build system, and that system does not run on each host.
//! This module does the same steps for the files that the generator reads. It copies the uapi
//! directories, applies the edits of scripts/headers_install.sh, and writes the wrapper headers
//! that Kbuild writes for the `mandatory-y` and `generic-y` lists.

use crate::Result;
use std::fs;
use std::path::Path;

/// The directories with the uAPI headers of the Linux tree. `fetch` unpacks them.
pub(crate) const UAPI_DIRS: &[&str] = &[
    "include/uapi",
    "arch/x86/include/uapi",
    "arch/arm64/include/uapi",
    "arch/riscv/include/uapi",
];

/// Writes the headers of `linux_arch` into `dest/include`.
pub(crate) fn build(tree: &Path, linux_arch: &str, dest: &Path) -> Result {
    if dest.exists() {
        fs::remove_dir_all(dest).map_err(|e| format!("{}: {e}", dest.display()))?;
    }
    let include = dest.join("include");
    let arch_uapi = format!("arch/{linux_arch}/include/uapi");
    copy_headers(&tree.join("include/uapi"), &include)?;
    copy_headers(&tree.join(&arch_uapi), &include)?;

    // Kbuild writes `asm/X.h` with one include of `asm-generic/X.h` for each header in these lists
    // that the architecture does not have.
    let mut wrappers = kbuild_list(tree, "include/uapi/asm-generic/Kbuild", "mandatory-y")?;
    wrappers.extend(kbuild_list(tree, &format!("{arch_uapi}/asm/Kbuild"), "generic-y")?);
    let asm = include.join("asm");
    fs::create_dir_all(&asm).map_err(|e| format!("{}: {e}", asm.display()))?;
    for header in wrappers {
        let path = asm.join(&header);
        if !path.exists() {
            fs::write(&path, format!("#include <asm-generic/{header}>\n"))
                .map_err(|e| format!("{}: {e}", path.display()))?;
        }
    }
    Ok(())
}

/// Gives the file names after `key +=` in a Kbuild file.
fn kbuild_list(tree: &Path, path: &str, key: &str) -> Result<Vec<String>> {
    let text = fs::read_to_string(tree.join(path)).map_err(|e| format!("{path}: {e}"))?;
    Ok(text
        .lines()
        .filter_map(|l| l.strip_prefix(key)?.trim_start().strip_prefix("+="))
        .flat_map(str::split_whitespace)
        .map(String::from)
        .collect())
}

fn copy_headers(from: &Path, to: &Path) -> Result {
    let entries = fs::read_dir(from).map_err(|e| format!("{}: {e}", from.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("{}: {e}", from.display()))?;
        let path = entry.path();
        let target = to.join(entry.file_name());
        if path.is_dir() {
            copy_headers(&path, &target)?;
        } else if path.extension().is_some_and(|e| e == "h") {
            let text = fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            fs::create_dir_all(to).map_err(|e| format!("{}: {e}", to.display()))?;
            fs::write(&target, install_edits(&text))
                .map_err(|e| format!("{}: {e}", target.display()))?;
        }
    }
    Ok(())
}

fn is_word(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// Replaces each `word` in `line` where `before` is true for the character before it and `after`
/// is true for the character after it. The start and the end of the line give `None`. If `eat` is
/// true, the replacement also removes the character after the word.
fn replace_word(
    line: &str,
    word: &str,
    before: fn(Option<char>) -> bool,
    after: fn(Option<char>) -> bool,
    with: &str,
    eat: bool,
) -> String {
    let mut out = String::with_capacity(line.len());
    let mut rest = line;
    while let Some(i) = rest.find(word) {
        let prev = rest[..i].chars().next_back().or_else(|| out.chars().next_back());
        let next = rest[i + word.len()..].chars().next();
        out.push_str(&rest[..i]);
        rest = &rest[i + word.len()..];
        if before(prev) && after(next) {
            out.push_str(with);
            if eat && let Some(c) = next {
                rest = &rest[c.len_utf8()..];
            }
        } else {
            out.push_str(word);
        }
    }
    out.push_str(rest);
    out
}

/// The edits of scripts/headers_install.sh. The script also removes the `__KERNEL__` blocks. The
/// generator does not define `__KERNEL__`, so the preprocessor removes them.
fn install_edits(text: &str) -> String {
    let space_or_paren = |c: Option<char>| c.is_some_and(|c| c.is_whitespace() || c == '(');
    let space = |c: Option<char>| c.is_some_and(char::is_whitespace);
    let space_or_end = |c: Option<char>| c.is_none_or(char::is_whitespace);
    let not_word = |c: Option<char>| c.is_none_or(|c| !is_word(c));
    let start_space_or_paren = |c: Option<char>| c.is_none_or(|c| c.is_whitespace() || c == '(');
    let mut out = String::with_capacity(text.len());
    for line in text.lines() {
        if line.starts_with("#include <linux/compiler.h>") {
            out.push('\n');
            continue;
        }
        let mut l = line.to_string();
        for word in ["__user", "__force", "__iomem"] {
            l = replace_word(&l, word, space_or_paren, space, "", true);
        }
        l = replace_word(&l, "__attribute_const__", not_word, space_or_end, "", false);
        l = replace_word(&l, "__packed", not_word, not_word, "__attribute__((packed))", false);
        for word in ["inline", "asm", "volatile"] {
            let with = format!("__{word}__");
            l = replace_word(&l, word, start_space_or_paren, start_space_or_paren, &with, false);
        }
        for directive in ["#ifndef", "#define", "#endif"] {
            if let Some(rest) = l.strip_prefix(directive) {
                let trimmed = rest.trim_start();
                let guard = if directive == "#endif" {
                    trimmed.strip_prefix("/*").map(|r| ("/* ", r.trim_start()))
                } else {
                    Some(("", trimmed))
                };
                if let Some((lead, name)) = guard
                    && let Some(name) = name.strip_prefix("_UAPI")
                {
                    l = format!("{directive} {lead}{name}");
                }
            }
        }
        out.push_str(&l.replace("__ASSEMBLY__", "__ASSEMBLER__"));
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::install_edits;

    #[test]
    fn the_edits_of_headers_install() {
        let text = "#ifndef _UAPI_LINUX_X_H\n\
                    #define _UAPI_LINUX_X_H\n\
                    #include <linux/compiler.h>\n\
                    int f(void __user *p, char __user *q);\n\
                    struct s { int a; } __packed;\n\
                    static inline int g(void);\n\
                    #ifndef __ASSEMBLY__\n\
                    int my_user_count;\n\
                    #endif /* _UAPI_LINUX_X_H */\n";
        let want = "#ifndef _LINUX_X_H\n\
                    #define _LINUX_X_H\n\
                    \n\
                    int f(void *p, char *q);\n\
                    struct s { int a; } __attribute__((packed));\n\
                    static __inline__ int g(void);\n\
                    #ifndef __ASSEMBLER__\n\
                    int my_user_count;\n\
                    #endif /* _LINUX_X_H */\n";
        assert_eq!(install_edits(text), want);
    }
}
