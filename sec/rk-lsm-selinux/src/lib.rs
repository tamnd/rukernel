//! SELinux, as security/selinux of Linux.
//!
//! SELinux gives each task and each object a security context, and a policy tells which
//! accesses a context can do. `load_policy` writes the binary policy to the file `load` of
//! selinuxfs, which is mounted on `/sys/fs/selinux`. This crate has the module, selinuxfs
//! ([`selinuxfs`]), the read of the binary policy ([`policydb`]) with its bitmaps
//! ([`ebitmap`]) and its rules ([`avtab`]), the security server ([`server`] and [`services`])
//! with its table of SIDs ([`sidtab`]), the text of the contexts ([`context`]), the classes of
//! the kernel ([`classmap`]), the access vector cache ([`avc`]), the SIDs of the tasks with
//! their change at an exec and their attributes in `/proc/PID/attr` ([`task`]), the labels of
//! the files ([`inode`]), the checks of the access to the files and to the open files
//! ([`file`]) and of the operations on the names of the directories ([`namei`]), and the
//! labels of the new files and the changes of the labels ([`xattr`]).
//!
//! The module is active when the command line has `selinux=1`, when `lsm=` names it, or with
//! `security=selinux`. With `selinux=0` it is not active. The module starts in permissive
//! mode: a denial makes an audit record and does not fail the call. `enforcing=1` on the
//! command line, or a write of 1 to `/sys/fs/selinux/enforce`, selects the enforcing mode.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod avc;
pub mod avtab;
pub mod classmap;
pub mod context;
pub mod ebitmap;
pub mod file;
pub mod inode;
pub mod namei;
pub mod policydb;
pub mod selinuxfs;
pub mod server;
pub mod services;
pub mod sidtab;
pub mod task;
pub mod xattr;

use crate::classmap::class;
use crate::namei::Link;
pub use crate::server::Policy;
use alloc::format;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use rk_frame::sync::SpinLock;
use rk_vfs::cred::Cred;
use rk_vfs::dentry::Location;
use rk_vfs::file::File;
use rk_vfs::inode::{Inode, Result, SetAttr};
use rk_vfs::security::blob::Blob;
use rk_vfs::security::{
    BlobSizes, Bprm, FLAG_EXCLUSIVE, FLAG_LEGACY_MAJOR, LsmId, LsmInfo, Order, SecurityHooks, Task,
    id,
};

/// The hooks of SELinux.
struct SeLinux;

impl SecurityHooks for SeLinux {
    fn bprm_creds_for_exec(&self, bprm: &mut Bprm<'_>) -> Result<()> {
        task::bprm_creds_for_exec(bprm)
    }

    fn getselfattr(&self, attr: u64, t: &Task<'_>) -> Result<Vec<u8>> {
        task::getattr(attr, t)
    }

    fn setselfattr(&self, attr: u64, ctx: &[u8], _flags: u64) -> Result<()> {
        task::setattr(attr, ctx).map(|_| ())
    }

    fn getprocattr(&self, t: &Task<'_>, name: &str) -> Option<Result<Vec<u8>>> {
        Some(task::getprocattr(t, name))
    }

    fn setprocattr(&self, name: &str, value: &[u8]) -> Option<Result<usize>> {
        Some(task::setprocattr(name, value))
    }

    fn inode_alloc_security(&self, _inode: &dyn Inode, blob: &Blob) {
        inode::alloc_security(blob);
    }

    fn inode_getsecurity(
        &self,
        inode: &dyn Inode,
        at: Option<&Location>,
        name: &[u8],
    ) -> Option<Result<Vec<u8>>> {
        inode::getsecurity(inode, at, name)
    }

    fn inode_listsecurity(&self, inode: &dyn Inode, at: Option<&Location>) -> Vec<Vec<u8>> {
        inode::listsecurity(inode, at)
    }

    fn inode_permission(
        &self,
        cred: &Cred,
        inode: &dyn Inode,
        at: Option<&Location>,
        mask: u32,
    ) -> Result<()> {
        file::inode_permission(cred, inode, at, mask)
    }

    fn file_alloc_security(&self, f: &File) {
        file::alloc_security(f);
    }

    fn file_open(&self, f: &File, cred: &Cred, flags: u32) -> Result<()> {
        file::file_open(f, cred, flags)
    }

    fn file_permission(&self, f: &File, mask: u32) -> Result<()> {
        file::file_permission(f, mask)
    }

    fn file_lock(&self, f: &File, _cmd: u32) -> Result<()> {
        file::file_lock(f)
    }

    fn file_fcntl(&self, f: &File, cmd: u32, arg: u64) -> Result<()> {
        file::file_fcntl(f, cmd, arg)
    }

    fn file_ioctl(&self, f: &File, cmd: u32, _arg: u64) -> Result<()> {
        file::file_ioctl(f, cmd)
    }

    fn mmap_file(&self, f: Option<&File>, _reqprot: u64, prot: u64, flags: u64) -> Result<()> {
        file::mmap_file(f, prot, flags)
    }

    fn inode_getattr(&self, at: &Location) -> Result<()> {
        file::inode_getattr(at)
    }

    fn inode_setattr(
        &self,
        inode: &dyn Inode,
        at: Option<&Location>,
        attr: &SetAttr,
    ) -> Result<()> {
        file::inode_setattr(inode, at, attr)
    }

    fn path_truncate(&self, at: &Location) -> Result<()> {
        file::path_truncate(at)
    }

    fn file_truncate(&self, f: &File) -> Result<()> {
        file::file_truncate(f)
    }

    fn inode_create(&self, dir: &Location, name: &[u8], _mode: u32) -> Result<()> {
        namei::may_create(dir, name, class::FILE)
    }

    fn inode_mkdir(&self, dir: &Location, name: &[u8], _mode: u32) -> Result<()> {
        namei::may_create(dir, name, class::DIR)
    }

    fn inode_mknod(&self, dir: &Location, name: &[u8], mode: u32, _dev: u64) -> Result<()> {
        namei::may_create(dir, name, inode::mode_to_class(mode))
    }

    fn inode_symlink(&self, dir: &Location, name: &[u8], _target: &[u8]) -> Result<()> {
        namei::may_create(dir, name, class::LNK_FILE)
    }

    fn inode_link(&self, old: &Location, dir: &Location, _name: &[u8]) -> Result<()> {
        namei::may_link(dir, old, Link::Link)
    }

    fn inode_unlink(&self, dir: &Location, at: &Location) -> Result<()> {
        namei::may_link(dir, at, Link::Unlink)
    }

    fn inode_rmdir(&self, dir: &Location, at: &Location) -> Result<()> {
        namei::may_link(dir, at, Link::Rmdir)
    }

    fn inode_rename(
        &self,
        old_dir: &Location,
        old: &Location,
        new_dir: &Location,
        name: &[u8],
        new: Option<&Location>,
    ) -> Result<()> {
        namei::may_rename(old_dir, old, new_dir, name, new)
    }

    fn inode_init_security(
        &self,
        inode: &dyn Inode,
        dir: &Location,
        name: Option<&[u8]>,
        xattrs: &mut Vec<(Vec<u8>, Vec<u8>)>,
    ) -> Result<()> {
        xattr::init_security(inode, dir, name, xattrs)
    }

    fn inode_setxattr(
        &self,
        inode: &dyn Inode,
        at: Option<&Location>,
        name: &[u8],
        value: &[u8],
        _flags: u32,
    ) -> Result<()> {
        xattr::setxattr(inode, at, name, value)
    }

    fn inode_post_setxattr(&self, inode: &dyn Inode, name: &[u8], value: &[u8], _flags: u32) {
        xattr::post_setxattr(inode, name, value);
    }

    fn inode_setsecurity(
        &self,
        inode: &dyn Inode,
        at: Option<&Location>,
        name: &[u8],
        value: &[u8],
        _flags: u32,
    ) -> Option<Result<()>> {
        xattr::setsecurity(inode, at, name, value)
    }

    fn inode_removexattr(
        &self,
        inode: &dyn Inode,
        at: Option<&Location>,
        name: &[u8],
    ) -> Result<()> {
        xattr::removexattr(inode, at, name)
    }
}

/// The description of the module, as `DEFINE_LSM(selinux)` of Linux. SELinux is a major module
/// that `security=selinux` selects, and it cannot be active with another exclusive module, as
/// AppArmor.
pub static LSM: LsmInfo = LsmInfo {
    id: LsmId { name: "selinux", id: id::SELINUX },
    order: Order::Mutable,
    flags: FLAG_LEGACY_MAJOR | FLAG_EXCLUSIVE,
    blobs: BlobSizes {
        cred: task::CRED_BLOB,
        file: file::FILE_BLOB,
        inode: inode::INODE_BLOB,
        ..BlobSizes::NONE
    },
    hooks: &SeLinux,
};

/// The names of the policy capabilities in the order of their numbers, `selinux_policycap_names`
/// of Linux.
pub const POLICYCAP_NAMES: [&str; 15] = [
    "network_peer_controls",
    "open_perms",
    "extended_socket_class",
    "always_check_network",
    "cgroup_seclabel",
    "nnp_nosuid_transition",
    "genfs_seclabel_symlinks",
    "ioctl_skip_cloexec",
    "userspace_initial_context",
    "netlink_xperm",
    "netif_wildcard",
    "genfs_seclabel_wildcard",
    "functionfs_seclabel",
    "memfd_class",
    "bpf_token_perms",
];

/// The module is active, `selinux_enabled_boot` of Linux.
static ENABLED: AtomicBool = AtomicBool::new(false);

/// The mode is enforcing, `selinux_state.enforcing` of Linux.
static ENFORCING: AtomicBool = AtomicBool::new(false);

/// The policy, after the first load.
static POLICY: SpinLock<Option<Arc<Policy>>> = SpinLock::new(None);

/// The number of policy loads, the `policyload` of the status page.
static POLICYLOAD: AtomicU32 = AtomicU32::new(0);

/// The number of changes of the status page, two for each change. A reader of the page
/// with `mmap` reads the number before and after the other values, and an odd number tells
/// that a change is in progress, as `selinux_status_update_setenforce` of Linux.
static SEQUENCE: AtomicU32 = AtomicU32::new(0);

/// Serializes the policy loads and the changes of the mode, as `selinux_state.policy_mutex`
/// of Linux.
static POLICY_MUTEX: SpinLock<()> = SpinLock::new(());

/// Tells if the module is active.
pub fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

/// Tells if the mode is enforcing.
pub fn enforcing() -> bool {
    ENFORCING.load(Ordering::Relaxed)
}

/// The loaded policy, or `None` before the first load, as `selinux_initialized` of Linux tells.
pub fn policy() -> Option<Arc<Policy>> {
    POLICY.lock().clone()
}

/// Tells if a policy is loaded.
pub fn initialized() -> bool {
    POLICY.lock().is_some()
}

/// The process ID and the name of the current process.
#[cfg(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64")))]
fn current() -> (u32, Vec<u8>) {
    rk_proc::current_thread().map_or((0, Vec::new()), |t| {
        let p = t.process();
        (p.pid(), p.comm())
    })
}

/// The process ID and the name of the current process. A build for the host has no process.
#[cfg(not(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64"))))]
fn current() -> (u32, Vec<u8>) {
    (0, Vec::new())
}

/// The SID of the current task, as `current_sid` of Linux.
pub fn current_sid() -> u32 {
    task::cred_sid(&rk_vfs::cred::current())
}

/// Tells if the module can be active, from the values of the parameters `selinux=`, `lsm=`
/// and `security=` of the command line, as `selinux_enabled_setup` of Linux. `selinux=` takes
/// a number, and a value that is not 0 makes the module active. Without `selinux=`, the
/// module is active only if `lsm=` names it, or if `security=` is `selinux` and there is no
/// `lsm=`.
pub fn wanted(selinux: Option<&str>, lsm: Option<&str>, security: Option<&str>) -> bool {
    match selinux.and_then(parse_int) {
        Some(v) => v != 0,
        None => match lsm {
            Some(l) => l.split(',').any(|m| m == "selinux"),
            None => security == Some("selinux"),
        },
    }
}

/// Parses a number as `kstrtoint` with the base 0: decimal, octal with `0`, or hex with `0x`.
fn parse_int(s: &str) -> Option<i64> {
    let s = s.strip_suffix('\n').unwrap_or(s);
    let (neg, s) = match s.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, s.strip_prefix('+').unwrap_or(s)),
    };
    let v = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        i64::from_str_radix(hex, 16).ok()?
    } else if s.len() > 1 && s.starts_with('0') {
        i64::from_str_radix(&s[1..], 8).ok()?
    } else {
        s.parse().ok()?
    };
    Some(if neg { -v } else { v })
}

/// Starts the module after `rk_vfs::security::init`, as `selinux_init` and `init_sel_fs` of
/// Linux. `enforcing` is the value of the parameter `enforcing=` of the command line. The
/// type `selinuxfs` and its mount point `/sys/fs/selinux` are there only if the module is
/// active.
pub fn init(enforcing: Option<&str>) {
    let active = rk_vfs::security::modules().iter().any(|m| m.info.id.id == id::SELINUX);
    if !active {
        return;
    }
    rk_frame::println!("SELinux:  Initializing.");
    ENABLED.store(true, Ordering::Relaxed);
    ENFORCING.store(enforcing.and_then(parse_int).is_some_and(|v| v != 0), Ordering::Relaxed);
    rk_vfs::fstype::register(selinuxfs::FS_TYPE);
    rk_fs_sys::add_fs_mount_point("selinux");
}

/// Changes the mode, as `sel_write_enforce` of Linux. A change makes an `MAC_STATUS` audit
/// record and updates the status page. A change to the enforcing mode removes the decisions
/// of the cache, because a denial in permissive mode adds the permissions to the cache.
pub fn set_enforcing(new: bool) {
    let _guard = POLICY_MUTEX.lock();
    let old = ENFORCING.swap(new, Ordering::Relaxed);
    if old == new {
        return;
    }
    let (auid, ses) = rk_net::netlink::audit::login_ids();
    let text = format!(
        "enforcing={} old_enforcing={} auid={auid} ses={ses} enabled=1 old-enabled=1 lsm=selinux res=1",
        u8::from(new),
        u8::from(old)
    );
    rk_net::netlink::audit::log_lsm(rk_net::netlink::audit::MAC_STATUS, &text);
    if new {
        avc::reset(0);
    }
    SEQUENCE.fetch_add(2, Ordering::Relaxed);
}

/// Loads a binary policy with [`server::load_policy`] and makes an `MAC_POLICY_LOAD` audit
/// record, as `sel_write_load` of Linux.
///
/// # Errors
///
/// `EINVAL` if the policy is bad.
pub fn load_policy(data: &[u8]) -> rk_vfs::inode::Result<()> {
    server::load_policy(data)?;
    let (auid, ses) = rk_net::netlink::audit::login_ids();
    let text = format!("auid={auid} ses={ses} lsm=selinux res=1");
    rk_net::netlink::audit::log_lsm(rk_net::netlink::audit::MAC_POLICY_LOAD, &text);
    Ok(())
}

/// Tells if the policy refuses the classes and permissions that it does not have, the file
/// `deny_unknown` of selinuxfs, as `!security_get_allow_unknown()` of Linux. Before the
/// first load the value is 1.
pub fn deny_unknown() -> bool {
    policy().is_none_or(|p| !p.db.allow_unknown)
}

/// Tells if the policy load fails when a class or a permission of the kernel is not in the
/// policy, the file `reject_unknown` of selinuxfs.
pub fn reject_unknown() -> bool {
    policy().is_some_and(|p| p.db.reject_unknown)
}

/// Tells if the policy has MLS, the file `mls` of selinuxfs.
pub fn mls_enabled() -> bool {
    policy().is_some_and(|p| p.db.mls)
}

/// The status page, `struct selinux_kernel_status` of Linux: the version 1 of the format, the
/// sequence number, the mode, the number of policy loads and `deny_unknown`.
pub fn status() -> [u8; 20] {
    let words = [
        1,
        SEQUENCE.load(Ordering::Relaxed),
        u32::from(enforcing()),
        POLICYLOAD.load(Ordering::Relaxed),
        u32::from(deny_unknown()),
    ];
    let mut out = [0; 20];
    for (i, w) in words.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&w.to_ne_bytes());
    }
    out
}

/// Serializes the unit tests that change the policy or the mode.
#[cfg(test)]
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_parameters_of_the_command_line_select_the_module() {
        assert!(!wanted(None, None, None));
        assert!(wanted(Some("1"), None, None));
        assert!(!wanted(Some("0"), Some("selinux"), None));
        assert!(wanted(None, Some("capability,selinux"), None));
        assert!(!wanted(None, Some("capability,apparmor"), Some("selinux")));
        assert!(wanted(None, None, Some("selinux")));
        assert!(!wanted(None, None, Some("apparmor")));
        assert!(wanted(Some("x"), Some("selinux"), None));
        assert_eq!(parse_int("-0x10"), Some(-16));
        assert_eq!(parse_int("010\n"), Some(8));
        assert_eq!(parse_int("y"), None);
    }

    #[test]
    fn a_policy_load_and_a_change_of_the_mode_update_the_status() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let before = status();
        assert_eq!(&before[..4], &1u32.to_ne_bytes());
        load_policy(include_bytes!("../tests/rk_test.35.bin")).unwrap();
        assert!(initialized() && mls_enabled() && deny_unknown() && !reject_unknown());
        assert_eq!(load_policy(b"bad"), Err(rk_abi::Errno::EINVAL));
        set_enforcing(true);
        let after = status();
        assert_eq!(&after[8..12], &1u32.to_ne_bytes());
        let seq = |s: &[u8; 20]| u32::from_ne_bytes([s[4], s[5], s[6], s[7]]);
        assert!(seq(&after) >= seq(&before) + 4 && seq(&after) % 2 == 0);
        set_enforcing(false);
        assert!(!enforcing());
    }
}
