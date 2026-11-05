//! Process file descriptors: `pidfd_open`, `pidfd_send_signal` and `pidfd_getfd`, and pidfs,
//! the file system of their inodes.
//!
//! A process file descriptor refers to one process. `poll` gives `POLLIN` when the process
//! ended. This is the model of kernel/pid.c and kernel/fork.c of Linux.
//!
//! Each descriptor has an inode in the one internal mount of pidfs, as fs/pidfs.c of Linux. The
//! inode number is the serial number of the process, which no other process of the boot has, so
//! two descriptors of one process have the same device and inode number in `fstat`, and a file
//! handle of the inode opens a new descriptor of the process.

use crate::cx::{Cx, SysResult};
use alloc::format;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use rk_abi::Errno;
use rk_abi::native::open::{
    O_ACCMODE, O_CLOEXEC, O_EXCL, O_LARGEFILE, O_NONBLOCK, O_RDONLY, O_RDWR,
};
use rk_frame::sync::Once;
use rk_proc::pid_namespace;
use rk_proc::signal::{NSIG, SI_USER, SIGINFO_SIZE, SigInfo};
use rk_proc::{Pid, Process};
use rk_vfs::Location;
use rk_vfs::file::{File, FileOps, events};
use rk_vfs::inode::{Inode, InodeRef, Metadata, SetAttr, mode};
use rk_vfs::user_ns::IdKind;
use rk_vfs::wait::PollTable;
use zerocopy::{Immutable, IntoBytes};

/// `PIDFD_NONBLOCK`: a wait for the process does not block.
const PIDFD_NONBLOCK: u32 = O_NONBLOCK;
/// `PIDFD_THREAD`: the descriptor refers to a thread. rukernel gives the process of the thread.
const PIDFD_THREAD: u32 = O_EXCL;

/// `PID_FS_MAGIC` of include/uapi/linux/magic.h.
pub(crate) const PID_FS_MAGIC: u64 = 0x5049_4446;
/// `FD_PIDFS_ROOT` of include/uapi/linux/fcntl.h: the root of pidfs as the `mountdirfd` of
/// `open_by_handle_at`.
pub(crate) const FD_PIDFS_ROOT: i32 = -10002;
/// `FILEID_KERNFS` of include/linux/exportfs.h: a handle of pidfs is the 64 bit inode number in
/// two words.
const FILEID_KERNFS: i32 = 0xfe;

/// The device of pidfs.
fn dev() -> u64 {
    static DEV: Once<u64> = Once::new();
    *DEV.call_once(rk_vfs::inode::anon_dev)
}

/// The root directory of pidfs. No lookup finds a name in it.
struct PidfsRoot;

impl Inode for PidfsRoot {
    fn metadata(&self) -> Metadata {
        Metadata {
            dev: dev(),
            ino: 1,
            mode: mode::S_IFDIR | 0o755,
            nlink: 2,
            ..Metadata::default()
        }
    }

    fn set_attr(&self, _attr: &SetAttr) -> rk_vfs::inode::Result<()> {
        Err(Errno::EOPNOTSUPP)
    }

    fn fs_magic(&self) -> u64 {
        PID_FS_MAGIC
    }
}

/// The inode of a process file descriptor. The inode number is the serial number of the
/// process, as `pid->ino` of Linux.
struct PidfsInode {
    ino: u64,
}

impl Inode for PidfsInode {
    /// The attributes of an anonymous inode of Linux: a regular file with the mode 0700 of
    /// `pidfs_init_inode`.
    fn metadata(&self) -> Metadata {
        Metadata {
            dev: dev(),
            ino: self.ino,
            mode: mode::S_IFREG | 0o700,
            nlink: 1,
            blksize: rk_mm::PAGE_SIZE as u32,
            ..Metadata::default()
        }
    }

    /// pidfs refuses each change of the attributes, as `anon_inode_setattr` of Linux.
    fn set_attr(&self, _attr: &SetAttr) -> rk_vfs::inode::Result<()> {
        Err(Errno::EOPNOTSUPP)
    }

    fn file_handle(&self) -> Option<(i32, Vec<u32>)> {
        Some((FILEID_KERNFS, alloc::vec![self.ino as u32, (self.ino >> 32) as u32]))
    }

    fn fs_magic(&self) -> u64 {
        PID_FS_MAGIC
    }
}

/// The root of the internal mount of pidfs, as `pidfs_mnt` of Linux.
fn root() -> &'static Location {
    static ROOT: Once<Location> = Once::new();
    ROOT.call_once(|| Location::detached(Arc::new(PidfsRoot)))
}

/// Tells if `at` is in the mount of pidfs, so that it is a process file descriptor or the root
/// of pidfs.
pub(crate) fn in_pidfs(at: &Location) -> bool {
    Arc::ptr_eq(&at.mount, &root().mount)
}

/// The operations of a process file descriptor.
struct PidFd {
    process: Arc<Process>,
}

/// Tells if the parent reaped `process`, so that it is not in the table of the processes.
fn reaped(process: &Arc<Process>) -> bool {
    rk_proc::find_process(process.pid()).is_none_or(|p| !Arc::ptr_eq(&p, process))
}

impl FileOps for PidFd {
    fn pollable(&self) -> bool {
        true
    }

    fn poll_wait(&self, _file: &File, table: &mut PollTable) {
        table.add(self.process.exit_poll());
    }

    fn poll(&self, _file: &File) -> u32 {
        if self.process.is_zombie() { events::POLLIN } else { 0 }
    }

    fn as_any(&self) -> Option<&dyn Any> {
        Some(self)
    }

    /// The ID of the process in the PID namespace of the reader, or 0 if the reader does not
    /// see it, or -1 after the parent reaped it, as `pidfd_show_fdinfo` of Linux. `NSpid` gives
    /// the ID in each namespace from the namespace of the reader down to the namespace of the
    /// process.
    fn fdinfo(&self, _file: &File) -> Vec<u8> {
        let p = &self.process;
        if reaped(p) {
            return b"Pid:\t-1\nNSpid:\t-1\n".to_vec();
        }
        let viewer = rk_proc::current_thread().map(|t| t.process().clone());
        let ns = viewer.as_ref().and_then(|v| v.pid_ns().cloned());
        let nr = pid_namespace::pid_nr_ns(p.pid(), ns.as_ref());
        let mut out = format!("Pid:\t{nr}\nNSpid:");
        if nr == 0 {
            out.push_str("\t0");
        } else {
            for n in pid_namespace::numbers(p.pid(), p.pid_ns(), ns.as_ref()) {
                out.push_str(&format!("\t{n}"));
            }
        }
        out.push('\n');
        out.into_bytes()
    }
}

/// Makes the file of a process file descriptor for `process`, with a new dentry of its inode in
/// the mount of pidfs, as `pidfs_alloc_file` of Linux.
fn new_file(process: Arc<Process>, flags: u32) -> Arc<File> {
    let root = root();
    let inode: InodeRef = Arc::new(PidfsInode { ino: process.serial() });
    let at = Location { mount: root.mount.clone(), dentry: root.dentry.tmp_child(inode, false) };
    File::with_ops(Arc::new(PidFd { process }), Some(at), O_RDWR | flags)
}

/// Makes a process file descriptor for `process`, for `pidfd_open` and `CLONE_PIDFD`. The
/// descriptor has `FD_CLOEXEC`, as in Linux.
///
/// # Errors
///
/// Gives `EMFILE` if the table is full.
pub(crate) fn open(cx: &Cx<'_>, process: Arc<Process>, flags: u32) -> Result<i32, Errno> {
    cx.files()?.lock().insert(new_file(process, flags), true)
}

/// `open_by_handle_at` of a handle of pidfs, as `pidfs_export_operations` of Linux. The handle
/// opens a new descriptor of the process until its parent reaps it. `flags` can have only the
/// flags of a process file descriptor.
///
/// # Errors
///
/// Gives `EINVAL` for another flag, and `ESTALE` if no process has the inode number.
pub(crate) fn open_by_handle(cx: &Cx<'_>, ty: i32, words: &[u32], flags: u32) -> SysResult {
    let valid = O_ACCMODE | O_NONBLOCK | O_CLOEXEC | O_EXCL | O_LARGEFILE;
    if flags & !valid != 0 {
        return Err(Errno::EINVAL);
    }
    let (&[lo, hi, ..], FILEID_KERNFS) = (words, ty) else { return Err(Errno::ESTALE) };
    let ino = u64::from(lo) | (u64::from(hi) << 32);
    let process =
        rk_proc::processes().into_iter().find(|p| p.serial() == ino).ok_or(Errno::ESTALE)?;
    let file = new_file(process, flags & (O_NONBLOCK | O_EXCL));
    Ok(cx.files()?.lock().insert(file, flags & O_CLOEXEC != 0)? as u64)
}

/// `PIDFS_IOCTL_MAGIC` of include/uapi/linux/pidfd.h: the type of the `ioctl` commands.
const PIDFS_IOCTL_MAGIC: u32 = 0xff;
/// The number of `PIDFD_GET_INFO`, `_IOWR(0xFF, 11, struct pidfd_info)`. The size in the command
/// is the size of the structure of the caller.
const PIDFD_GET_INFO_NR: u32 = 11;
/// `FS_IOC_GETVERSION`, `_IOR('v', 1, long)`.
const FS_IOC_GETVERSION: u32 = 0x8008_7601;

/// The bits of `pidfd_info.mask`.
const PIDFD_INFO_PID: u64 = 1 << 0;
const PIDFD_INFO_CREDS: u64 = 1 << 1;
const PIDFD_INFO_CGROUPID: u64 = 1 << 2;
const PIDFD_INFO_EXIT: u64 = 1 << 3;
const PIDFD_INFO_COREDUMP: u64 = 1 << 4;
/// `PIDFD_INFO_SIZE_VER0`: the size of the first version of `struct pidfd_info`.
const PIDFD_INFO_SIZE_VER0: usize = 64;

/// The bits of `pidfd_info.coredump_mask`.
const PIDFD_COREDUMPED: u32 = 1 << 0;
const PIDFD_COREDUMP_SKIP: u32 = 1 << 1;
const PIDFD_COREDUMP_USER: u32 = 1 << 2;
const PIDFD_COREDUMP_ROOT: u32 = 1 << 3;

/// `struct pidfd_info` of include/uapi/linux/pidfd.h.
#[derive(Default, IntoBytes, Immutable)]
#[repr(C)]
struct PidfdInfo {
    mask: u64,
    cgroupid: u64,
    pid: u32,
    tgid: u32,
    ppid: u32,
    ruid: u32,
    rgid: u32,
    euid: u32,
    egid: u32,
    suid: u32,
    sgid: u32,
    fsuid: u32,
    fsgid: u32,
    exit_code: i32,
    coredump_mask: u32,
    spare1: u32,
}

/// The `PIDFD_COREDUMP_*` bit of the `dumpable` value of a process, as `pidfs_coredump_mask` of
/// Linux.
fn coredump_mask(dumpable: u8) -> u32 {
    use rk_proc::coredump::{SUID_DUMP_ROOT, SUID_DUMP_USER};
    match dumpable {
        SUID_DUMP_USER => PIDFD_COREDUMP_USER,
        SUID_DUMP_ROOT => PIDFD_COREDUMP_ROOT,
        _ => PIDFD_COREDUMP_SKIP,
    }
}

/// `PIDFD_GET_INFO`: the IDs, the credentials, the cgroup and the exit status of the process,
/// as `pidfd_info` in fs/pidfs.c of Linux. `size` is the size of the structure of the caller.
/// The exit status is there only after the parent reaped the process, and the IDs and the
/// credentials only before.
///
/// # Errors
///
/// Gives `EINVAL` for a structure smaller than the first version, `EREMOTE` for a process out of
/// the PID namespace of the caller, and `ESRCH` for a reaped process without `PIDFD_INFO_EXIT`
/// in the mask.
fn get_info(cx: &Cx<'_>, process: &Arc<Process>, size: usize, arg: u64) -> SysResult {
    if arg == 0 || size < PIDFD_INFO_SIZE_VER0 {
        return Err(Errno::EINVAL);
    }
    let mask: u64 = cx.read_val(arg)?;
    // Only a process in the PID namespace of the caller or in a namespace below it gives its
    // information, as `pid_in_current_pidns` of Linux.
    if !pid_namespace::is_descendant(process.pid_ns(), cx.process().pid_ns()) {
        return Err(Errno::EREMOTE);
    }
    let mut info = PidfdInfo::default();
    let gone = reaped(process);
    let status = process.exit_status();
    if mask & PIDFD_INFO_EXIT != 0
        && gone
        && let Some(status) = status
    {
        info.mask |= PIDFD_INFO_EXIT | PIDFD_INFO_CGROUPID;
        info.exit_code = status.0;
        info.cgroupid = rk_fs_cgroup::cgroup_ino(process.cgroup());
    }
    if mask & PIDFD_INFO_COREDUMP != 0 {
        info.mask |= PIDFD_INFO_COREDUMP;
        // A process that wrote a core dump has the bit 0x80 in its status, as `WCOREDUMP`.
        if status.is_some_and(|s| s.0 & 0x80 != 0) {
            info.coredump_mask = PIDFD_COREDUMPED | coredump_mask(process.dumpable());
        } else if !gone && process.vm().is_some() {
            info.coredump_mask = coredump_mask(process.dumpable());
        }
    }
    if gone {
        if mask & PIDFD_INFO_EXIT == 0 {
            return Err(Errno::ESRCH);
        }
    } else {
        // The credentials in the user namespace of the caller, as `from_kuid_munged` of Linux.
        let c = process.cred();
        let me = cx.process().cred();
        let u = |id| me.user_ns.from_kid_munged(IdKind::Uid, id);
        let g = |id| me.user_ns.from_kid_munged(IdKind::Gid, id);
        (info.ruid, info.rgid, info.euid, info.egid) = (u(c.uid), g(c.gid), u(c.euid), g(c.egid));
        (info.suid, info.sgid, info.fsuid, info.fsgid) =
            (u(c.suid), g(c.sgid), u(c.fsuid), g(c.fsgid));
        info.mask |= PIDFD_INFO_CREDS;
        if info.cgroupid == 0 {
            info.cgroupid = rk_fs_cgroup::cgroup_ino(process.cgroup());
            info.mask |= PIDFD_INFO_CGROUPID;
        }
        // The IDs in the PID namespace of the caller, as `pidfd_info` of Linux. A process that
        // the caller does not see gives `ESRCH`.
        info.pid = cx.vnr(process.pid());
        if info.pid == 0 {
            return Err(Errno::ESRCH);
        }
        info.ppid = cx.vnr(process.ppid());
        info.tgid = info.pid;
        info.mask |= PIDFD_INFO_PID;
    }
    // The caller gets the part of the structure that it knows, and zeros after the part that
    // the kernel knows, as `copy_struct_to_user` of Linux.
    let bytes = info.as_bytes();
    let n = size.min(bytes.len());
    cx.write_bytes(arg, &bytes[..n])?;
    if size > n {
        cx.write_bytes(arg + n as u64, &alloc::vec![0; size - n])?;
    }
    Ok(0)
}

/// The `ioctl` commands of a process file descriptor, as `pidfd_ioctl` in fs/pidfs.c of Linux:
/// `PIDFD_GET_INFO`, `FS_IOC_GETVERSION`, and the commands that open a file of a namespace of
/// the process, as a link in `/proc/PID/ns`. Gives `None` if `file` is not a process file
/// descriptor.
///
/// # Errors
///
/// Gives `ENOTTY` for another command, `ESRCH` if the process ended, `EINVAL` if `arg` is not 0
/// for a namespace, `EACCES` if the caller cannot trace the process, and `EOPNOTSUPP` for the
/// user namespace, as Linux without `CONFIG_USER_NS`.
pub(crate) fn ioctl(cx: &Cx<'_>, file: &File, cmd: u32, arg: u64) -> Option<SysResult> {
    let pidfd = file.ops().as_any().and_then(|a| a.downcast_ref::<PidFd>())?;
    let process = &pidfd.process;
    let (ty, nr) = ((cmd >> 8) & 0xff, cmd & 0xff);
    if cmd == FS_IOC_GETVERSION {
        if arg == 0 {
            return Some(Err(Errno::EINVAL));
        }
        // The generation of the inode is 0 on a 64 bit kernel, as `pidfs_gen` of Linux.
        return Some(cx.write_val(arg, &0u32).map(|()| 0));
    }
    if ty != PIDFS_IOCTL_MAGIC {
        return Some(Err(Errno::ENOTTY));
    }
    if nr == PIDFD_GET_INFO_NR {
        return Some(get_info(cx, process, ((cmd >> 16) & 0x3fff) as usize, arg));
    }
    use rk_vfs::nsfs::NsKind;
    let kind = match cmd {
        0xff01 => NsKind::Cgroup,
        0xff02 => NsKind::Ipc,
        0xff03 => NsKind::Mnt,
        0xff04 => NsKind::Net,
        0xff05 => NsKind::Pid,
        0xff06 => return Some(open_pid_for_children(cx, process, arg)),
        0xff07 => NsKind::Time,
        0xff08 => return Some(open_time_for_children(cx, process, arg)),
        0xff09 => NsKind::User,
        0xff0a => NsKind::Uts,
        _ => return Some(Err(Errno::ENOTTY)),
    };
    Some(open_ns(cx, process, kind, arg))
}

/// Opens the file of the time namespace for the children of `process`, for
/// `PIDFD_GET_TIME_FOR_CHILDREN_NAMESPACE`.
fn open_time_for_children(cx: &Cx<'_>, process: &Arc<Process>, arg: u64) -> SysResult {
    open_inode(cx, process, arg, |p| Ok(crate::ns::time_inode(p.time_ns_for_children())))
}

/// Opens the file of the PID namespace for the children of `process`, for
/// `PIDFD_GET_PID_FOR_CHILDREN_NAMESPACE`.
fn open_pid_for_children(cx: &Cx<'_>, process: &Arc<Process>, arg: u64) -> SysResult {
    open_inode(cx, process, arg, crate::ns::pid_for_children_inode)
}

/// Opens the file of the namespace `kind` of `process` for a `PIDFD_GET_*_NAMESPACE` command,
/// as `open_namespace` of Linux. The new descriptor has `FD_CLOEXEC`.
fn open_ns(cx: &Cx<'_>, process: &Arc<Process>, kind: rk_vfs::nsfs::NsKind, arg: u64) -> SysResult {
    open_inode(cx, process, arg, |p| Ok(crate::ns::inode_of(p, kind)?))
}

/// Opens the file of a namespace of `process` that `inode` gives, after the checks of
/// `pidfd_ioctl` of Linux.
fn open_inode(
    cx: &Cx<'_>,
    process: &Arc<Process>,
    arg: u64,
    inode: impl FnOnce(&Process) -> Result<InodeRef, Errno>,
) -> SysResult {
    // A zombie has no namespaces, as a task without `nsproxy` on Linux.
    if reaped(process) || process.is_zombie() {
        return Err(Errno::ESRCH);
    }
    if arg != 0 {
        return Err(Errno::EINVAL);
    }
    if !Arc::ptr_eq(process, cx.process()) && !cx.process().cred().may_ptrace(&process.cred()) {
        return Err(Errno::EACCES);
    }
    let inode = inode(process)?;
    let file = File::open_inode(Location::detached(inode), O_RDONLY);
    Ok(cx.files()?.lock().insert(file, true)? as u64)
}

/// Gives the process of the process file descriptor `fd`.
///
/// # Errors
///
/// Gives `EBADF` if `fd` is not open, or if it is not a process file descriptor.
pub(crate) fn process_of(cx: &Cx<'_>, fd: u64) -> Result<Arc<Process>, Errno> {
    let file = cx.file(fd)?;
    let pidfd = file.ops().as_any().and_then(|a| a.downcast_ref::<PidFd>()).ok_or(Errno::EBADF)?;
    Ok(pidfd.process.clone())
}

/// The process of `fd` for `pidfd_send_signal`: a process file descriptor, or a directory
/// `/proc/PID` of a process, as `pidfd_to_pid` and `tgid_pidfd_to_pid` of Linux.
///
/// # Errors
///
/// Gives `EBADF` for another file, and `ESRCH` if the process of the directory ended.
fn signal_target_of(cx: &Cx<'_>, fd: u64) -> Result<Arc<Process>, Errno> {
    /// `PROC_SUPER_MAGIC` of include/uapi/linux/magic.h.
    const PROC_SUPER_MAGIC: u64 = 0x9fa0;
    if let Ok(process) = process_of(cx, fd) {
        return Ok(process);
    }
    let file = cx.file(fd)?;
    let at = file.location().ok_or(Errno::EBADF)?;
    let inode = at.inode();
    let is_dir =
        inode.metadata().mode & rk_vfs::inode::mode::S_IFMT == rk_vfs::inode::mode::S_IFDIR;
    let in_root = at.dentry.parent().is_some_and(|p| Arc::ptr_eq(&p, at.mount.root()));
    if inode.fs_magic() != PROC_SUPER_MAGIC || !is_dir || !in_root {
        return Err(Errno::EBADF);
    }
    let pid: Pid = core::str::from_utf8(&at.dentry.name())
        .ok()
        .and_then(|n| n.parse().ok())
        .ok_or(Errno::EBADF)?;
    // The directory of a process that ended has no files, also when a new process has the PID
    // now. The signal does not go to the new process, as `pidfd_send_signal` of Linux.
    if inode.stale() {
        return Err(Errno::ESRCH);
    }
    rk_proc::find_process(pid).ok_or(Errno::ESRCH)
}

pub(crate) fn pidfd_open(cx: &Cx<'_>, pid: u64, flags: u64) -> SysResult {
    let flags = u32::try_from(flags).map_err(|_| Errno::EINVAL)?;
    let pid = pid as i32;
    if flags & !(PIDFD_NONBLOCK | PIDFD_THREAD) != 0 || pid <= 0 {
        return Err(Errno::EINVAL);
    }
    let pid = cx.find_vpid(pid as u64).ok_or(Errno::ESRCH)?;
    let process = match rk_proc::find_process(pid) {
        Some(p) => p,
        // The ID of a thread that is not the leader gives `ENOENT`, as in Linux.
        None => match rk_proc::find_thread(pid) {
            Some(t) if flags & PIDFD_THREAD != 0 => t.process().clone(),
            Some(_) => return Err(Errno::ENOENT),
            None => return Err(Errno::ESRCH),
        },
    };
    Ok(open(cx, process, flags & PIDFD_NONBLOCK)? as u64)
}

pub(crate) fn pidfd_send_signal(
    cx: &Cx<'_>,
    fd: u64,
    sig: u64,
    uinfo: u64,
    flags: u64,
) -> SysResult {
    if flags != 0 || sig > u64::from(NSIG) {
        return Err(Errno::EINVAL);
    }
    let process = signal_target_of(cx, fd)?;
    if process.is_zombie() {
        return Err(Errno::ESRCH);
    }
    let info = if uinfo == 0 {
        let mut info = SigInfo::new(sig as u32, SI_USER, cx.process().pid());
        info.uid = cx.process().cred().uid;
        info
    } else {
        let b = cx.read_bytes(uinfo, SIGINFO_SIZE)?;
        let mut raw = [0u8; SIGINFO_SIZE];
        raw.copy_from_slice(&b);
        let mut info = SigInfo::from_bytes(&raw);
        // As `rt_sigqueueinfo`: only the kernel sends a signal with a code of 0 or more to
        // another process.
        if info.signo != sig as u32 {
            return Err(Errno::EINVAL);
        }
        if info.code >= 0 && !Arc::ptr_eq(&process, cx.process()) {
            return Err(Errno::EPERM);
        }
        info.signo = sig as u32;
        info
    };
    // The permission of `kill`, as `check_kill_permission` in kernel/signal.c of Linux.
    crate::signal::may_signal(cx, &process, sig as u32)?;
    if sig != 0 {
        rk_proc::send_signal(&process, info);
    }
    Ok(0)
}

pub(crate) fn pidfd_getfd(cx: &Cx<'_>, fd: u64, target: u64, flags: u64) -> SysResult {
    if flags != 0 {
        return Err(Errno::EINVAL);
    }
    let process = process_of(cx, fd)?;
    // The caller must be able to attach to the target, as `pidfd_getfd` in kernel/pid.c of
    // Linux (`PTRACE_MODE_ATTACH_REALCREDS`).
    if !Arc::ptr_eq(&process, cx.process()) && !cx.process().cred().may_ptrace(&process.cred()) {
        return Err(Errno::EPERM);
    }
    let files = process.files().ok_or(Errno::ESRCH)?;
    let file = files.lock().file(target as i32)?;
    Ok(cx.files()?.lock().insert(file, true)? as u64)
}
