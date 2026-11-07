//! The files of AppArmor in securityfs, `/sys/kernel/security/apparmor`, as
//! security/apparmor/apparmorfs.c of Linux.
//!
//! - `features/`: the features of the kernel ([`crate::features`]).
//! - `.load`, `.replace` and `.remove`: a write loads, replaces or removes profiles of the
//!   namespace of the process. Each write must be at the position 0 and is whole.
//! - `profiles`: a line `NAME (MODE)` for each profile.
//! - `revision`: the number of changes of the policy.
//! - `.access`, `.stacked`, `.ns_stacked`, `.ns_level` and `.ns_name`: the queries and the
//!   state of the label of the process.
//! - `policy/`: the namespace, with `profiles/`, `raw_data/`, `namespaces/`, `revision` and its
//!   own `.load`, `.replace` and `.remove`.
//!
//! On Linux, `policy` is a link to the directory `.policy` of the internal file system
//! `apparmorfs`. Here it is a directory.

use crate::features;
use crate::policy::{self, Change, ROOT};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_vfs::inode::Result;
use rk_vfs::security::securityfs::{self, Entry, Tree};

/// The files and the directories that are always there, with their paths below the top. The
/// directories that have files are not in the list.
const FIXED: &[(&str, Entry)] = &[
    (".access", Entry::File(0o666)),
    (".stacked", Entry::File(0o444)),
    (".ns_stacked", Entry::File(0o444)),
    (".ns_level", Entry::File(0o444)),
    (".ns_name", Entry::File(0o444)),
    ("profiles", Entry::File(0o444)),
    (".load", Entry::File(0o666)),
    (".replace", Entry::File(0o666)),
    (".remove", Entry::File(0o666)),
    ("revision", Entry::File(0o444)),
    ("policy/profiles", Entry::Dir),
    ("policy/raw_data", Entry::Dir),
    ("policy/revision", Entry::File(0o444)),
    ("policy/.load", Entry::File(0o640)),
    ("policy/.replace", Entry::File(0o640)),
    ("policy/.remove", Entry::File(0o640)),
    ("policy/namespaces", Entry::Dir),
];

/// The tree of AppArmor.
struct AppArmorFs;

/// All the paths of the tree with their entries, in order.
fn paths() -> Vec<(String, Entry)> {
    let mut out: Vec<(String, Entry)> =
        FIXED.iter().map(|(p, e)| (String::from(*p), e.clone())).collect();
    let at = out.iter().position(|(p, _)| p == "profiles").map_or(out.len(), |i| i + 1);
    let features =
        features::FILES.iter().map(|(p, _)| (format!("features/{p}"), Entry::File(0o444)));
    out.splice(at..at, features);
    out
}

impl Tree for AppArmorFs {
    fn entry(&self, path: &str) -> Option<Entry> {
        if path.is_empty() {
            return Some(Entry::Dir);
        }
        let all = paths();
        if let Some((_, e)) = all.iter().find(|(p, _)| p == path) {
            return Some(e.clone());
        }
        let dir = all.iter().any(|(p, _)| p.strip_prefix(path).is_some_and(|r| r.starts_with('/')));
        dir.then_some(Entry::Dir)
    }

    fn list(&self, path: &str) -> Vec<(String, Entry)> {
        let mut out: Vec<(String, Entry)> = Vec::new();
        for (p, e) in paths() {
            let rest = if path.is_empty() {
                Some(p.as_str())
            } else {
                p.strip_prefix(path).and_then(|r| r.strip_prefix('/'))
            };
            let Some(rest) = rest else { continue };
            let (name, e) = match rest.split_once('/') {
                Some((name, _)) => (name, Entry::Dir),
                None => (rest, e),
            };
            if !out.iter().any(|(n, _)| n == name) {
                out.push((String::from(name), e));
            }
        }
        out
    }

    fn open(&self, path: &str, _flags: u32) -> Result<()> {
        // A process that cannot see the policy cannot open `profiles`, as `profiles_open` of
        // Linux.
        if path == "profiles" && !policy::view_capable(&rk_vfs::cred::current()) {
            return Err(Errno::EACCES);
        }
        Ok(())
    }

    fn read(&self, path: &str) -> Result<Vec<u8>> {
        if let Some(f) = path.strip_prefix("features/") {
            return features::get(f).map(features::Value::text).ok_or(Errno::EINVAL);
        }
        let text = match path {
            // The process has the label `unconfined` of the root namespace: one profile and no
            // stack.
            ".stacked" | ".ns_stacked" => String::from("no\n"),
            ".ns_level" => String::from("0\n"),
            ".ns_name" => format!("{}\n", ROOT.name),
            "profiles" => profiles_text(),
            "revision" | "policy/revision" => format!("{}\n", ROOT.revision()),
            // A read of `.access` before a query gives nothing, as `simple_transaction_read`.
            ".access" => String::new(),
            // The other files take only writes.
            _ => return Err(Errno::EINVAL),
        };
        Ok(text.into_bytes())
    }

    fn write(&self, path: &str, offset: u64, data: &[u8]) -> Result<usize> {
        let change = match path {
            ".load" | "policy/.load" => Change::Load,
            ".replace" | "policy/.replace" => Change::Replace,
            ".remove" | "policy/.remove" => Change::Remove,
            // `.access` takes a query of a label. No query is there yet.
            ".access" if offset != 0 => return Err(Errno::ESPIPE),
            _ => return Err(Errno::EINVAL),
        };
        // A write must be whole, as `aa_simple_write_to_buffer` of Linux.
        if offset != 0 {
            return Err(Errno::ESPIPE);
        }
        policy::may_manage(&rk_vfs::cred::current(), change)?;
        match change {
            Change::Remove => policy::remove(&ROOT, data),
            _ => policy::replace(&ROOT, change, data),
        }
    }
}

/// The text of `profiles`: a line for each profile, as `seq_show_profile` of Linux.
fn profiles_text() -> String {
    let mut s = String::new();
    for p in ROOT.profiles() {
        s.push_str(&format!("{} ({})\n", p.name, p.mode.name()));
    }
    s
}

static TREE: AppArmorFs = AppArmorFs;

/// Adds the directory `apparmor` to securityfs, as `aa_create_aafs` of Linux.
pub(crate) fn init() {
    securityfs::add_tree("apparmor", &TREE);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(dir: &str) -> Vec<String> {
        TREE.list(dir).into_iter().map(|(n, _)| n).collect()
    }

    #[test]
    fn the_tree_has_the_files_of_linux() {
        let top = names("");
        for n in [
            ".access", ".load", ".replace", ".remove", "profiles", "revision", "features", "policy",
        ] {
            assert!(top.iter().any(|t| t == n), "{n}");
        }
        assert_eq!(TREE.entry(".load"), Some(Entry::File(0o666)));
        assert_eq!(TREE.entry("policy/.load"), Some(Entry::File(0o640)));
        assert_eq!(TREE.entry("features/domain"), Some(Entry::Dir));
        assert_eq!(TREE.entry("features/dom"), None);
        assert_eq!(TREE.entry("policy/profiles"), Some(Entry::Dir));
        assert!(TREE.list("policy/profiles").is_empty());
        assert_eq!(
            names("policy"),
            ["profiles", "raw_data", "revision", ".load", ".replace", ".remove", "namespaces"]
        );
        assert!(names("features").iter().any(|n| n == "policy"));
        assert_eq!(names("features/policy/versions"), ["v5", "v6", "v7", "v8", "v9"]);
        assert_eq!(TREE.read("features/domain/version").unwrap(), b"1.2\n");
        assert_eq!(TREE.read(".ns_name").unwrap(), b"root\n");
        assert_eq!(TREE.read("revision").unwrap(), b"0\n");
        assert_eq!(TREE.read("profiles").unwrap(), b"");
        assert_eq!(TREE.read(".load"), Err(Errno::EINVAL));
    }

    #[test]
    fn a_write_must_be_whole_and_the_policy_cannot_unpack_yet() {
        assert_eq!(TREE.write(".load", 1, b"x"), Err(Errno::ESPIPE));
        assert_eq!(TREE.write(".replace", 0, b"x"), Err(Errno::EPROTO));
        assert_eq!(TREE.write("policy/.remove", 0, b"/bin/true"), Err(Errno::ENOENT));
        assert_eq!(TREE.write("profiles", 0, b"x"), Err(Errno::EINVAL));
        assert_eq!(TREE.write(".access", 0, b"label\0x"), Err(Errno::EINVAL));
    }
}
