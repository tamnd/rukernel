//! The Linux Security Module framework, as security/security.c and security/lsm_init.c of Linux.
//!
//! An LSM implements some of the hooks of [`SecurityHooks`]. The kernel calls the functions of
//! this module at the points where Linux calls `security_*`. Each function calls the hook of each
//! active module in the order of the boot, and the first error stops the call, as `call_int_hook`
//! of Linux.
//!
//! At boot, [`init`] makes the order of the modules from `lsm=` or the default list, as
//! `lsm_order_parse` of Linux, and gives each module the offsets of its parts of the security
//! blobs. The capability module is always the first module.

pub mod blob;
pub mod capability;
pub mod hooks;
pub mod securityfs;
#[cfg(test)]
mod tests;

pub use blob::{Blob, BlobSizes, IpcClass, IpcSecurity};
pub use hooks::{HOOK_COUNT, HOOK_NAMES, SecurityHooks, hook_index};

use crate::cred::{Cred, IpcOwner};
use crate::dentry::Location;
use crate::file::File;
use crate::inode::{Inode, Result};
use alloc::string::String;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_frame::sync::{Once, SpinLock};

/// The IDs of the modules, `LSM_ID_*` of include/uapi/linux/lsm.h.
pub mod id {
    /// No module, `LSM_ID_UNDEF`.
    pub const UNDEF: u64 = 0;
    /// The capability module.
    pub const CAPABILITY: u64 = 100;
    /// SELinux.
    pub const SELINUX: u64 = 101;
    /// Smack.
    pub const SMACK: u64 = 102;
    /// TOMOYO.
    pub const TOMOYO: u64 = 103;
    /// AppArmor.
    pub const APPARMOR: u64 = 104;
    /// Yama.
    pub const YAMA: u64 = 105;
    /// LoadPin.
    pub const LOADPIN: u64 = 106;
    /// SafeSetID.
    pub const SAFESETID: u64 = 107;
    /// Lockdown.
    pub const LOCKDOWN: u64 = 108;
    /// The BPF LSM.
    pub const BPF: u64 = 109;
    /// Landlock.
    pub const LANDLOCK: u64 = 110;
    /// IMA.
    pub const IMA: u64 = 111;
    /// EVM.
    pub const EVM: u64 = 112;
    /// IPE.
    pub const IPE: u64 = 113;
}

/// The attributes of `lsm_get_self_attr`, `LSM_ATTR_*` of include/uapi/linux/lsm.h.
pub mod attr {
    /// No attribute, `LSM_ATTR_UNDEF`.
    pub const UNDEF: u64 = 0;
    /// The current context of the task.
    pub const CURRENT: u64 = 100;
    /// The context for the next `execve`.
    pub const EXEC: u64 = 101;
    /// The context of the files that the task makes.
    pub const FSCREATE: u64 = 102;
    /// The context of the keys that the task makes.
    pub const KEYCREATE: u64 = 103;
    /// The context before the last `execve`.
    pub const PREV: u64 = 104;
    /// The context of the sockets that the task makes.
    pub const SOCKCREATE: u64 = 105;
}

/// The name and the number of a module, as `struct lsm_id` of Linux.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LsmId {
    /// The name in `lsm=` and in /sys/kernel/security/lsm.
    pub name: &'static str,
    /// The `LSM_ID_*` value.
    pub id: u64,
}

/// The place of a module in the order, as `enum lsm_order` of Linux.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Order {
    /// Always first, as the capability module.
    First,
    /// In the order of `lsm=` or of the default list.
    Mutable,
    /// Always last, as IMA and EVM.
    Last,
}

/// The module can be active only if no other exclusive module is active, `LSM_FLAG_EXCLUSIVE`.
pub const FLAG_EXCLUSIVE: u32 = 1 << 1;
/// The module is a major module that `security=` selects, `LSM_FLAG_LEGACY_MAJOR`.
pub const FLAG_LEGACY_MAJOR: u32 = 1 << 0;

/// The description of a module, as `struct lsm_info` of Linux.
pub struct LsmInfo {
    /// The name and the number.
    pub id: LsmId,
    /// The place in the order.
    pub order: Order,
    /// The `FLAG_*` bits.
    pub flags: u32,
    /// The size of the part of each blob that the module uses.
    pub blobs: BlobSizes,
    /// The hooks.
    pub hooks: &'static dyn SecurityHooks,
}

/// An active module and the offsets of its parts of the blobs.
#[derive(Clone, Copy)]
pub struct Active {
    /// The module.
    pub info: &'static LsmInfo,
    /// The byte offset of the part of the module in each blob. A module that asked for no space
    /// in a blob has the offset 0 there.
    pub offsets: BlobSizes,
}

/// A file of a security module below `/proc/sys`, as a `ctl_table` entry that a module of Linux
/// gives to `register_sysctl`. The value is one `int`.
pub struct Sysctl {
    /// The path below `/proc/sys`, for example `kernel/apparmor_restrict_unprivileged_userns`.
    pub name: &'static str,
    /// The mode of the file.
    pub mode: u32,
    /// Gives the value.
    pub get: fn() -> i32,
    /// Sets the value, with the checks of the module.
    pub set: fn(i32) -> Result<()>,
}

/// The files that the modules give below `/proc/sys`.
static SYSCTLS: SpinLock<Vec<&'static Sysctl>> = SpinLock::new(Vec::new());

/// Adds the files `table` below `/proc/sys`, as `register_sysctl` of Linux.
pub fn register_sysctls(table: &'static [Sysctl]) {
    SYSCTLS.lock().extend(table.iter());
}

/// The files that the modules give below `/proc/sys`.
pub fn sysctls() -> Vec<&'static Sysctl> {
    SYSCTLS.lock().clone()
}

/// The file `name` of a module below `/proc/sys`.
pub fn sysctl(name: &str) -> Option<&'static Sysctl> {
    SYSCTLS.lock().iter().copied().find(|s| s.name == name)
}

/// The modules after the boot order, and the sizes of the blobs.
pub struct State {
    /// The active modules in the order of the calls.
    pub active: Vec<Active>,
    /// The size of each blob.
    pub sizes: BlobSizes,
}

impl State {
    /// The names of the active modules, separated by commas, as /sys/kernel/security/lsm.
    pub fn names(&self) -> String {
        let mut s = String::new();
        for (i, a) in self.active.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str(a.info.id.name);
        }
        s
    }
}

/// The default order of the modules, `CONFIG_LSM` of Linux. A name without a module is skipped.
pub const DEFAULT_LSM: &str =
    "landlock,lockdown,yama,loadpin,safesetid,integrity,selinux,smack,tomoyo,apparmor,ipe,bpf";

/// The most modules that can be active, as `MAX_LSM_COUNT` of Linux.
pub const MAX_LSM_COUNT: usize = 16;

/// Makes the order of the modules from `available`, as `lsm_order_parse` and `lsm_prepare` of
/// Linux. `lsm` is the value of `lsm=`, or `None` for the default list. `legacy` is the value of
/// `security=`, which has no effect with `lsm=`.
pub fn prepare(available: &[&'static LsmInfo], lsm: Option<&str>, legacy: Option<&str>) -> State {
    let (list, legacy) = match lsm {
        Some(l) => (l, None),
        None => (DEFAULT_LSM, legacy),
    };
    let mut disabled = Vec::new();
    if let Some(legacy) = legacy {
        for m in available {
            if m.flags & FLAG_LEGACY_MAJOR != 0 && m.id.name != legacy {
                disabled.push(m.id.name);
            }
        }
    }
    let mut order: Vec<&'static LsmInfo> = Vec::new();
    let mut exclusive = false;
    let mut append = |m: &'static LsmInfo| {
        if order.iter().any(|o| o.id.name == m.id.name)
            || disabled.contains(&m.id.name)
            || order.len() == MAX_LSM_COUNT
        {
            return;
        }
        if m.flags & FLAG_EXCLUSIVE != 0 {
            if exclusive {
                return;
            }
            exclusive = true;
        }
        order.push(m);
    };
    for &m in available.iter().filter(|m| m.order == Order::First) {
        append(m);
    }
    for name in list.split(',') {
        for &m in available.iter().filter(|m| m.order == Order::Mutable && m.id.name == name) {
            append(m);
        }
    }
    if let Some(legacy) = legacy {
        for &m in available.iter().filter(|m| m.id.name == legacy) {
            append(m);
        }
    }
    for &m in available.iter().filter(|m| m.order == Order::Last) {
        append(m);
    }
    let mut sizes = BlobSizes::NONE;
    let active = order.into_iter().map(|info| Active { info, offsets: sizes.add(&info.blobs) });
    let active = active.collect();
    State { active, sizes }
}

/// The state after [`init`].
static STATE: Once<State> = Once::new();

/// The modules that other crates give before [`init`].
static REGISTERED: SpinLock<Vec<&'static LsmInfo>> = SpinLock::new(Vec::new());

/// The modules before [`init`]: only the capability module, with no blobs.
static EARLY: [Active; 1] = [Active { info: &capability::LSM, offsets: BlobSizes::NONE }];

/// Adds a module that [`init`] can make active, as `DEFINE_LSM` of Linux. A call after [`init`]
/// has no effect.
pub fn register(info: &'static LsmInfo) {
    REGISTERED.lock().push(info);
}

/// Makes the modules active, as `security_init` of Linux. `lsm` and `security` are the values
/// of the `lsm=` and `security=` parameters of the command line. Gives the names of the active
/// modules for the message `LSM: initializing lsm=...` of the boot.
pub fn init(lsm: Option<&str>, security: Option<&str>) -> String {
    let state = STATE.call_once(|| {
        let mut available: Vec<&'static LsmInfo> = alloc::vec![&capability::LSM];
        available.extend(REGISTERED.lock().iter().copied());
        prepare(&available, lsm, security)
    });
    state.names()
}

/// The active modules in the order of the calls.
pub fn modules() -> &'static [Active] {
    STATE.get().map_or(&EARLY[..], |s| &s.active[..])
}

/// The size of each blob. It is 0 before [`init`].
pub fn sizes() -> BlobSizes {
    STATE.get().map_or(BlobSizes::NONE, |s| s.sizes)
}

/// The names of the active modules, separated by commas.
pub fn lsm_names() -> String {
    STATE.get().map_or_else(|| String::from(capability::LSM.id.name), State::names)
}

/// Calls `f` for each module in `mods` and gives the first error, as `call_int_hook` of Linux.
pub fn first_error(
    mods: &[Active],
    mut f: impl FnMut(&dyn SecurityHooks) -> Result<()>,
) -> Result<()> {
    for m in mods {
        f(m.info.hooks)?;
    }
    Ok(())
}

/// Calls the hook `$hook` of each active module with the arguments, and gives the first error,
/// as `call_int_hook` of Linux.
macro_rules! call_int_hook {
    ($hook:ident $(, $arg:expr)*) => {
        first_error(modules(), |h| h.$hook($($arg),*))
    };
}

/// Calls the hook `$hook` of each active module with the arguments, as `call_void_hook` of
/// Linux.
macro_rules! call_void_hook {
    ($hook:ident $(, $arg:expr)*) => {
        for m in modules() {
            m.info.hooks.$hook($($arg),*);
        }
    };
}

/// A task for the hooks: a thread with its credentials, as the `task_struct` argument of the
/// hooks of Linux.
pub struct Task<'a> {
    /// The thread ID.
    pub pid: u32,
    /// The credentials of the task.
    pub cred: &'a Cred,
    /// The task blob, or `None` if the caller has only the process.
    pub security: Option<&'a Blob>,
}

/// An `execve` for the hooks, as `struct linux_binprm` of Linux.
pub struct Bprm<'a> {
    /// The name of the file that the caller gave.
    pub filename: &'a [u8],
    /// The file that runs. For a script, it is the script in `bprm_creds_for_exec`, and the
    /// interpreter in the hooks after it.
    pub file: &'a Location,
    /// The new credentials. The hooks can change them.
    pub cred: &'a mut Cred,
    /// The program gets the secure mode of `AT_SECURE`. A hook can set it.
    pub secureexec: bool,
    /// The credentials of the tracer if a tracer traces the task, as `LSM_UNSAFE_PTRACE` and
    /// `ptrace_parent` of Linux.
    pub tracer: Option<&'a Cred>,
}

/// A socket for the hooks, as `struct socket` of Linux.
pub struct Sock<'a> {
    /// The address family, `AF_*`.
    pub family: u32,
    /// The type, `SOCK_*`.
    pub kind: u32,
    /// The protocol.
    pub protocol: u32,
    /// The socket blob.
    pub security: &'a Blob,
    /// The addresses of the socket, or `None` for a new socket.
    pub names: Option<&'a dyn SockNames>,
}

/// The addresses of a socket for the hooks, as `getname` of `struct proto_ops` of Linux.
pub trait SockNames {
    /// The local address, as `getsockname`.
    fn name(&self) -> Vec<u8>;
    /// The address of the peer, as `getpeername`. `None` if the socket has no peer.
    fn peer_name(&self) -> Option<Vec<u8>>;
    /// The socket file of a Unix socket with a path name, as `unix_sk(sk)->path` of Linux.
    /// `None` for another socket.
    fn path(&self) -> Option<Location> {
        None
    }
    /// Calls `f` with the peer of the socket, as `unix_peer` of Linux. Gives `false` if the
    /// socket has no peer.
    fn with_peer(&self, f: &mut dyn FnMut(&Sock<'_>)) -> bool {
        let _ = f;
        false
    }
}

/// `security_capable`: the task with `cred` has the capability `cap`. `opts` has the
/// `CAP_OPT_*` bits.
pub fn capable(cred: &Cred, cap: u32, opts: u32) -> bool {
    call_int_hook!(capable, cred, cap, opts).is_ok()
}

/// `security_capable` after the capability module: the other active modules check the
/// capability `cap` of the task with `cred`. The caller has done the check of the capability
/// module, `cap_capable` of Linux, in the user namespace of the request.
pub fn capable_lsm(cred: &Cred, cap: u32, opts: u32) -> bool {
    modules()
        .iter()
        .filter(|m| m.info.id.id != id::CAPABILITY)
        .all(|m| m.info.hooks.capable(cred, cap, opts).is_ok())
}

/// `security_capget`.
pub fn capget(target: &Task<'_>) -> Result<()> {
    call_int_hook!(capget, target)
}

/// `security_capset`.
pub fn capset(new: &Cred, old: &Cred) -> Result<()> {
    call_int_hook!(capset, new, old)
}

/// `security_ptrace_access_check`.
pub fn ptrace_access_check(cred: &Cred, child: &Task<'_>, mode: u32) -> Result<()> {
    call_int_hook!(ptrace_access_check, cred, child, mode)
}

/// `security_ptrace_traceme`.
pub fn ptrace_traceme(parent: &Task<'_>) -> Result<()> {
    call_int_hook!(ptrace_traceme, parent)
}

/// `security_bprm_creds_for_exec`.
pub fn bprm_creds_for_exec(bprm: &mut Bprm<'_>) -> Result<()> {
    call_int_hook!(bprm_creds_for_exec, &mut *bprm)
}

/// `security_bprm_creds_from_file`.
pub fn bprm_creds_from_file(bprm: &mut Bprm<'_>) -> Result<()> {
    call_int_hook!(bprm_creds_from_file, &mut *bprm)
}

/// `security_bprm_check`.
pub fn bprm_check(bprm: &mut Bprm<'_>) -> Result<()> {
    call_int_hook!(bprm_check_security, &mut *bprm)
}

/// `security_bprm_committing_creds`.
pub fn bprm_committing_creds(bprm: &Bprm<'_>) {
    call_void_hook!(bprm_committing_creds, bprm);
}

/// `security_bprm_committed_creds`.
pub fn bprm_committed_creds(filename: &[u8], file: &Location) {
    call_void_hook!(bprm_committed_creds, filename, file);
}

/// The `sb_alloc_security` hooks, for [`blob::superblock_attach`].
fn sb_alloc_security(dev: u64, blob: &Blob) {
    call_void_hook!(sb_alloc_security, dev, blob);
}

/// The `sb_free_security` hooks, for [`blob::superblock_attach`].
fn sb_free_security(dev: u64, blob: &Blob) {
    call_void_hook!(sb_free_security, dev, blob);
}

/// The `inode_alloc_security` hooks, for [`blob::inode_attach`].
fn inode_alloc_security(inode: &dyn Inode, blob: &Blob) {
    call_void_hook!(inode_alloc_security, inode, blob);
}

/// `security_d_instantiate`.
fn d_instantiate(inode: &dyn Inode) {
    call_void_hook!(d_instantiate, inode);
}

/// `security_inode_permission`.
pub fn inode_permission(cred: &Cred, inode: &dyn Inode, mask: u32) -> Result<()> {
    call_int_hook!(inode_permission, cred, inode, mask)
}

/// `security_file_permission`.
pub fn file_permission(file: &File, mask: u32) -> Result<()> {
    call_int_hook!(file_permission, file, mask)
}

/// `security_file_alloc`.
pub fn file_alloc(file: &File) {
    call_void_hook!(file_alloc_security, file);
}

/// `security_file_free`.
pub fn file_free(file: &File) {
    call_void_hook!(file_free_security, file);
}

/// `security_file_ioctl`.
pub fn file_ioctl(file: &File, cmd: u32, arg: u64) -> Result<()> {
    call_int_hook!(file_ioctl, file, cmd, arg)
}

/// `security_mmap_file`.
pub fn mmap_file(file: Option<&File>, reqprot: u64, prot: u64, flags: u64) -> Result<()> {
    call_int_hook!(mmap_file, file, reqprot, prot, flags)
}

/// `security_file_mprotect`.
pub fn file_mprotect(file: Option<&File>, reqprot: u64, prot: u64) -> Result<()> {
    call_int_hook!(file_mprotect, file, reqprot, prot)
}

/// `security_file_lock`.
pub fn file_lock(file: &File, cmd: u32) -> Result<()> {
    call_int_hook!(file_lock, file, cmd)
}

/// `security_file_fcntl`.
pub fn file_fcntl(file: &File, cmd: u32, arg: u64) -> Result<()> {
    call_int_hook!(file_fcntl, file, cmd, arg)
}

/// `security_file_open`.
pub fn file_open(file: &File, cred: &Cred, flags: u32) -> Result<()> {
    call_int_hook!(file_open, file, cred, flags)
}

/// `security_path_unlink`.
pub fn path_unlink(dir: &Location, at: &Location) -> Result<()> {
    call_int_hook!(path_unlink, dir, at)
}

/// `security_path_mkdir`.
pub fn path_mkdir(dir: &Location, name: &[u8], mode: u32) -> Result<()> {
    call_int_hook!(path_mkdir, dir, name, mode)
}

/// `security_path_rmdir`.
pub fn path_rmdir(dir: &Location, at: &Location) -> Result<()> {
    call_int_hook!(path_rmdir, dir, at)
}

/// `security_path_mknod`.
pub fn path_mknod(dir: &Location, name: &[u8], mode: u32, dev: u64) -> Result<()> {
    call_int_hook!(path_mknod, dir, name, mode, dev)
}

/// `security_path_truncate`.
pub fn path_truncate(at: &Location) -> Result<()> {
    call_int_hook!(path_truncate, at)
}

/// `security_path_symlink`.
pub fn path_symlink(dir: &Location, name: &[u8], target: &[u8]) -> Result<()> {
    call_int_hook!(path_symlink, dir, name, target)
}

/// `security_path_link`.
pub fn path_link(old: &Location, dir: &Location, name: &[u8]) -> Result<()> {
    call_int_hook!(path_link, old, dir, name)
}

/// `security_path_rename`.
pub fn path_rename(
    old: &Location,
    dir: &Location,
    name: &[u8],
    new: Option<&Location>,
    flags: u32,
) -> Result<()> {
    call_int_hook!(path_rename, old, dir, name, new, flags)
}

/// `security_path_chmod`.
pub fn path_chmod(at: &Location, mode: u32) -> Result<()> {
    call_int_hook!(path_chmod, at, mode)
}

/// `security_path_chown`.
pub fn path_chown(at: &Location, uid: Option<u32>, gid: Option<u32>) -> Result<()> {
    call_int_hook!(path_chown, at, uid, gid)
}

/// `security_inode_getattr`.
pub fn inode_getattr(at: &Location) -> Result<()> {
    call_int_hook!(inode_getattr, at)
}

/// The arguments of `mount(2)` for the `sb_mount` hook, as `security_sb_mount` of Linux gives
/// them.
pub struct MountReq<'a> {
    /// The place of the mount.
    pub at: &'a Location,
    /// The source, `dev_name`, as the caller gives it.
    pub dev_name: Option<&'a [u8]>,
    /// The type of the file system.
    pub fstype: Option<&'a [u8]>,
    /// The `MS_*` flags without the magic number.
    pub flags: u32,
    /// The options, the data of `mount(2)`.
    pub data: Option<&'a [u8]>,
    /// The flags of the type `fstype`, or `None` if there is no such type, as `get_fs_type`.
    pub fs_flags: Option<FsFlags>,
    /// Looks up a path as the caller sees it, as `kern_path` with `LOOKUP_FOLLOW`.
    pub lookup: &'a dyn Fn(&[u8]) -> Result<Location>,
}

/// The flags of a type of a file system that the `sb_mount` hook reads, as `fs_flags` of
/// `struct file_system_type` of Linux.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FsFlags {
    /// `FS_REQUIRES_DEV`: the source is a block device.
    pub requires_dev: bool,
    /// `FS_BINARY_MOUNTDATA`: the data is not text.
    pub binary: bool,
}

/// `security_sb_mount`.
pub fn sb_mount(req: &MountReq<'_>) -> Result<()> {
    call_int_hook!(sb_mount, req)
}

/// `security_sb_umount`.
pub fn sb_umount(root: &Location, flags: u32) -> Result<()> {
    call_int_hook!(sb_umount, root, flags)
}

/// `security_sb_pivotroot`.
pub fn sb_pivotroot(old: &Location, new: &Location) -> Result<()> {
    call_int_hook!(sb_pivotroot, old, new)
}

/// `security_move_mount`.
pub fn move_mount(from: &Location, to: &Location) -> Result<()> {
    call_int_hook!(move_mount, from, to)
}

/// `security_file_truncate`.
pub fn file_truncate(file: &File) -> Result<()> {
    call_int_hook!(file_truncate, file)
}

/// `security_task_alloc`.
pub fn task_alloc(child: &Task<'_>, clone_flags: u64) -> Result<()> {
    call_int_hook!(task_alloc, child, clone_flags)
}

/// `security_task_free`.
pub fn task_free(blob: &Blob) {
    call_void_hook!(task_free, blob);
}

/// `security_task_fix_setuid`.
pub fn task_fix_setuid(new: &mut Cred, old: &Cred, flags: u32) -> Result<()> {
    call_int_hook!(task_fix_setuid, &mut *new, old, flags)
}

/// `security_task_fix_setgid`.
pub fn task_fix_setgid(new: &mut Cred, old: &Cred, flags: u32) -> Result<()> {
    call_int_hook!(task_fix_setgid, &mut *new, old, flags)
}

/// `security_task_fix_setgroups`.
pub fn task_fix_setgroups(new: &mut Cred, old: &Cred) -> Result<()> {
    call_int_hook!(task_fix_setgroups, &mut *new, old)
}

/// `security_task_setpgid`.
pub fn task_setpgid(target: &Task<'_>, pgid: u32) -> Result<()> {
    call_int_hook!(task_setpgid, target, pgid)
}

/// `security_task_getpgid`.
pub fn task_getpgid(target: &Task<'_>) -> Result<()> {
    call_int_hook!(task_getpgid, target)
}

/// `security_task_getsid`.
pub fn task_getsid(target: &Task<'_>) -> Result<()> {
    call_int_hook!(task_getsid, target)
}

/// `security_task_setnice`.
pub fn task_setnice(target: &Task<'_>, nice: i32) -> Result<()> {
    call_int_hook!(task_setnice, target, nice)
}

/// `security_task_setioprio`.
pub fn task_setioprio(target: &Task<'_>, ioprio: i32) -> Result<()> {
    call_int_hook!(task_setioprio, target, ioprio)
}

/// `security_task_getioprio`.
pub fn task_getioprio(target: &Task<'_>) -> Result<()> {
    call_int_hook!(task_getioprio, target)
}

/// `security_task_prlimit`.
pub fn task_prlimit(cred: &Cred, tcred: &Cred, flags: u32) -> Result<()> {
    call_int_hook!(task_prlimit, cred, tcred, flags)
}

/// `security_task_setscheduler`.
pub fn task_setscheduler(target: &Task<'_>) -> Result<()> {
    call_int_hook!(task_setscheduler, target)
}

/// `security_task_getscheduler`.
pub fn task_getscheduler(target: &Task<'_>) -> Result<()> {
    call_int_hook!(task_getscheduler, target)
}

/// `security_task_kill`.
pub fn task_kill(target: &Task<'_>, sig: u32, cred: &Cred) -> Result<()> {
    call_int_hook!(task_kill, target, sig, cred)
}

/// `security_create_user_ns`: the task with the credentials `cred` makes a user namespace, and
/// `new` are its credentials in the namespace.
pub fn userns_create(cred: &Cred, new: &Cred) -> Result<()> {
    call_int_hook!(userns_create, cred, new)
}

/// `security_task_prctl`: gives `None` if no module handles the option. The first result other
/// than `Ok(0)` stops the calls, as in Linux.
pub fn task_prctl(option: u32, args: [u64; 4]) -> Option<Result<u64>> {
    let mut rc = None;
    for m in modules() {
        if let Some(r) = m.info.hooks.task_prctl(option, args) {
            if r != Ok(0) {
                return Some(r);
            }
            rc = Some(r);
        }
    }
    rc
}

/// `security_socket_create`.
pub fn socket_create(family: u32, kind: u32, protocol: u32, kern: bool) -> Result<()> {
    call_int_hook!(socket_create, family, kind, protocol, kern)
}

/// `security_socket_post_create`.
pub fn socket_post_create(sock: &Sock<'_>, kern: bool) -> Result<()> {
    call_int_hook!(socket_post_create, sock, kern)
}

/// `security_socket_socketpair`.
pub fn socket_socketpair(a: &Sock<'_>, b: &Sock<'_>) -> Result<()> {
    call_int_hook!(socket_socketpair, a, b)
}

/// `security_socket_bind`.
pub fn socket_bind(sock: &Sock<'_>, addr: &[u8]) -> Result<()> {
    call_int_hook!(socket_bind, sock, addr)
}

/// `security_socket_connect`.
pub fn socket_connect(sock: &Sock<'_>, addr: &[u8]) -> Result<()> {
    call_int_hook!(socket_connect, sock, addr)
}

/// `security_socket_listen`.
pub fn socket_listen(sock: &Sock<'_>, backlog: i32) -> Result<()> {
    call_int_hook!(socket_listen, sock, backlog)
}

/// `security_socket_accept`.
pub fn socket_accept(sock: &Sock<'_>) -> Result<()> {
    call_int_hook!(socket_accept, sock)
}

/// `security_socket_sendmsg`. `addr` is the address of the destination and `flags` has the
/// `MSG_*` bits of the message.
pub fn socket_sendmsg(sock: &Sock<'_>, addr: Option<&[u8]>, flags: u32, len: usize) -> Result<()> {
    call_int_hook!(socket_sendmsg, sock, addr, flags, len)
}

/// `security_socket_recvmsg`.
pub fn socket_recvmsg(sock: &Sock<'_>, len: usize, flags: u32) -> Result<()> {
    call_int_hook!(socket_recvmsg, sock, len, flags)
}

/// `security_socket_getsockname`.
pub fn socket_getsockname(sock: &Sock<'_>) -> Result<()> {
    call_int_hook!(socket_getsockname, sock)
}

/// `security_socket_getpeername`.
pub fn socket_getpeername(sock: &Sock<'_>) -> Result<()> {
    call_int_hook!(socket_getpeername, sock)
}

/// `security_socket_getsockopt`.
pub fn socket_getsockopt(sock: &Sock<'_>, level: i32, name: i32) -> Result<()> {
    call_int_hook!(socket_getsockopt, sock, level, name)
}

/// `security_socket_setsockopt`.
pub fn socket_setsockopt(sock: &Sock<'_>, level: i32, name: i32) -> Result<()> {
    call_int_hook!(socket_setsockopt, sock, level, name)
}

/// `security_socket_shutdown`.
pub fn socket_shutdown(sock: &Sock<'_>, how: i32) -> Result<()> {
    call_int_hook!(socket_shutdown, sock, how)
}

/// `security_unix_stream_connect`: `sock` connects to the listener `other`. `new` is the socket
/// of the connection that the listener takes with `accept`. The caller holds the lock of
/// `other`.
pub fn unix_stream_connect(sock: &Sock<'_>, other: &Sock<'_>, new: &Sock<'_>) -> Result<()> {
    call_int_hook!(unix_stream_connect, sock, other, new)
}

/// `security_unix_may_send`: the Unix datagram socket `sock` connects or sends to `other`.
pub fn unix_may_send(sock: &Sock<'_>, other: &Sock<'_>) -> Result<()> {
    call_int_hook!(unix_may_send, sock, other)
}

/// `security_socket_getpeersec_stream`: the security context of the peer of `sock`, for
/// `SO_PEERSEC`. The first module that gives a context or an error stops the calls.
///
/// # Errors
///
/// Gives `ENOPROTOOPT` if no module gives a context, as Linux.
pub fn socket_getpeersec_stream(sock: &Sock<'_>) -> Result<Vec<u8>> {
    modules()
        .iter()
        .find_map(|m| m.info.hooks.socket_getpeersec_stream(sock))
        .unwrap_or(Err(Errno::ENOPROTOOPT))
}

/// `security_ipc_permission`, for [`Cred::ipc_permission`].
pub fn ipc_permission(cred: &Cred, ipc: &IpcOwner<'_>, flag: u32) -> Result<()> {
    call_int_hook!(ipc_permission, cred, ipc, flag)
}

/// `security_msg_queue_alloc`, `security_sem_alloc` or `security_shm_alloc`, by the class of
/// `ipc`. The caller makes the object only if the hooks give no error.
pub fn ipc_alloc(ipc: &IpcSecurity) -> Result<()> {
    match ipc.class() {
        IpcClass::Msg => call_int_hook!(msg_queue_alloc_security, ipc),
        IpcClass::Sem => call_int_hook!(sem_alloc_security, ipc),
        IpcClass::Shm => call_int_hook!(shm_alloc_security, ipc),
    }
}

/// `security_msg_queue_free`, `security_sem_free` or `security_shm_free`, for the drop of
/// [`IpcSecurity`].
fn ipc_free(ipc: &IpcSecurity) {
    match ipc.class() {
        IpcClass::Msg => call_void_hook!(msg_queue_free_security, ipc),
        IpcClass::Sem => call_void_hook!(sem_free_security, ipc),
        IpcClass::Shm => call_void_hook!(shm_free_security, ipc),
    }
}

/// `security_msg_queue_associate`, `security_sem_associate` or `security_shm_associate`, by
/// the class of `ipc`. An object with no security part has no hooks.
pub fn ipc_associate(ipc: &IpcOwner<'_>, flag: u32) -> Result<()> {
    match ipc.security.map(IpcSecurity::class) {
        Some(IpcClass::Msg) => call_int_hook!(msg_queue_associate, ipc, flag),
        Some(IpcClass::Sem) => call_int_hook!(sem_associate, ipc, flag),
        Some(IpcClass::Shm) => call_int_hook!(shm_associate, ipc, flag),
        None => Ok(()),
    }
}

/// `security_getprocattr`: the text of the attribute `name` of `task` for a file of
/// `/proc/PID/attr`. `lsmid` is the ID of the module of a module directory, or 0 for the
/// first module that has the attribute. With no such module, the result is `EINVAL`.
pub fn getprocattr(task: &Task<'_>, lsmid: u64, name: &str) -> Result<Vec<u8>> {
    for m in modules() {
        if lsmid != 0 && lsmid != m.info.id.id {
            continue;
        }
        if let Some(r) = m.info.hooks.getprocattr(task, name) {
            return r;
        }
    }
    Err(Errno::EINVAL)
}

/// `security_setprocattr`: a write of `value` to the attribute `name` of the caller, as
/// [`getprocattr`]. Gives the count of bytes that the module took.
pub fn setprocattr(lsmid: u64, name: &str, value: &[u8]) -> Result<usize> {
    for m in modules() {
        if lsmid != 0 && lsmid != m.info.id.id {
            continue;
        }
        if let Some(r) = m.info.hooks.setprocattr(name, value) {
            return r;
        }
    }
    Err(Errno::EINVAL)
}

/// The size of the header of `struct lsm_ctx` of `<linux/lsm.h>`: the ID, the flags, the size
/// of the entry and the size of the context.
pub const LSM_CTX_HEADER: usize = 32;

/// `LSM_FLAG_SINGLE`: `lsm_get_self_attr` gives the attribute of one module.
pub const LSM_FLAG_SINGLE: u32 = 1;

/// The result of [`getselfattr`].
#[derive(Debug, Default, PartialEq, Eq)]
pub struct SelfAttr {
    /// The `struct lsm_ctx` entries that fit, one after the other.
    pub entries: Vec<u8>,
    /// The size of all the entries, also of the entries that did not fit.
    pub total: u32,
    /// The count of entries.
    pub count: u32,
    /// An entry did not fit in the room.
    pub too_big: bool,
}

/// Adds the `struct lsm_ctx` entry of the module `id` with the context `ctx` to `out`, as
/// `lsm_fill_user_ctx` of Linux. The entry size is a multiple of 8.
fn push_ctx(out: &mut Vec<u8>, id: u64, ctx: &[u8]) {
    let len = (LSM_CTX_HEADER + ctx.len()).next_multiple_of(8);
    for v in [id, 0, len as u64, ctx.len() as u64] {
        out.extend_from_slice(&v.to_ne_bytes());
    }
    out.extend_from_slice(ctx);
    out.resize(out.len() + len - LSM_CTX_HEADER - ctx.len(), 0);
}

/// `security_getselfattr`: the attribute `attr` (an `LSM_ATTR_*` value) of `task` from each
/// module that has it, or from the module `single` only. `room` is the size of the buffer of
/// the caller. A module that gives `EOPNOTSUPP` has no entry. An entry that does not fit sets
/// `too_big`, and the next entries get no room, as Linux.
///
/// # Errors
///
/// Gives `EINVAL` for `LSM_ATTR_UNDEF`, and the first error of a module that is not
/// `EOPNOTSUPP`.
pub fn getselfattr(attr: u64, task: &Task<'_>, single: Option<u64>, room: u32) -> Result<SelfAttr> {
    if attr == attr::UNDEF {
        return Err(Errno::EINVAL);
    }
    let mut out = SelfAttr::default();
    let mut left = room as usize;
    for m in modules() {
        if single.is_some_and(|id| id != m.info.id.id) {
            continue;
        }
        let ctx = match m.info.hooks.getselfattr(attr, task) {
            Err(Errno::EOPNOTSUPP) => continue,
            r => r?,
        };
        let len = (LSM_CTX_HEADER + ctx.len()).next_multiple_of(8);
        if len > left {
            left = 0;
            out.too_big = true;
        } else {
            left -= len;
            push_ctx(&mut out.entries, m.info.id.id, &ctx);
            out.count += 1;
        }
        out.total = out.total.saturating_add(u32::try_from(len).unwrap_or(u32::MAX));
        if single.is_some() {
            break;
        }
    }
    Ok(out)
}

/// `security_setselfattr`: sets the attribute `attr` of the caller from the `struct lsm_ctx`
/// in `buf`, through the module with the ID of the entry.
///
/// # Errors
///
/// Gives `EINVAL` for flags, for a buffer smaller than the header or than the entry, and for an
/// entry smaller than its context. Gives `E2BIG` for a buffer larger than a page, and
/// `EOPNOTSUPP` if no active module has the ID or the module cannot set the attribute.
pub fn setselfattr(attr: u64, buf: &[u8], flags: u32) -> Result<()> {
    if flags != 0 || buf.len() < LSM_CTX_HEADER {
        return Err(Errno::EINVAL);
    }
    if buf.len() > 4096 {
        return Err(Errno::E2BIG);
    }
    let word = |i: usize| {
        let mut b = [0u8; 8];
        b.copy_from_slice(&buf[i * 8..i * 8 + 8]);
        u64::from_ne_bytes(b)
    };
    let (id, ctx_flags, len, ctx_len) = (word(0), word(1), word(2), word(3));
    let need = (LSM_CTX_HEADER as u64).checked_add(ctx_len);
    if (buf.len() as u64) < len || need.is_none_or(|n| len < n) {
        return Err(Errno::EINVAL);
    }
    let ctx = &buf[LSM_CTX_HEADER..LSM_CTX_HEADER + ctx_len as usize];
    match modules().iter().find(|m| m.info.id.id == id) {
        Some(m) => m.info.hooks.setselfattr(attr, ctx, ctx_flags),
        None => Err(Errno::EOPNOTSUPP),
    }
}

/// The IDs of the active modules in order, for `lsm_list_modules`.
pub fn module_ids() -> Vec<u64> {
    modules().iter().map(|m| m.info.id.id).collect()
}

/// The modules that have their own directory in `/proc/PID/attr`, with their IDs and their
/// names. Only Smack and AppArmor have one, as `attr_dir_stuff` of fs/proc/base.c of Linux. Yama
/// and the other modules have no attributes there, so LTP proc01 fails on a read of a directory
/// for them.
pub fn attr_modules() -> Vec<(u64, &'static str)> {
    modules()
        .iter()
        .filter(|m| matches!(m.info.id.id, id::SMACK | id::APPARMOR))
        .map(|m| (m.info.id.id, m.info.id.name))
        .collect()
}
