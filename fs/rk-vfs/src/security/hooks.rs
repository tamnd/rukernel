//! The table of the LSM hooks, as include/linux/lsm_hook_defs.h of Linux, and the trait that a
//! module implements.
//!
//! `HOOK_NAMES` has the names of all the hooks of Linux in the order of lsm_hook_defs.h. The
//! `SecurityHooks` trait has a method for each hook that rukernel calls now. Each method has a
//! default that allows the operation, so a module implements only the hooks that it uses, as a
//! module of Linux puts only some hooks in its `security_hook_list`.

use super::blob::{Blob, IpcSecurity};
use super::{Bprm, Sock, Task};
use crate::cred::{Cred, IpcOwner};
use crate::dentry::Location;
use crate::file::File;
use crate::inode::{Inode, Result};
use alloc::vec::Vec;

/// The names of the LSM hooks of Linux, in the order of include/linux/lsm_hook_defs.h.
pub static HOOK_NAMES: [&str; HOOK_COUNT] = [
    "binder_set_context_mgr",
    "binder_transaction",
    "binder_transfer_binder",
    "binder_transfer_file",
    "ptrace_access_check",
    "ptrace_traceme",
    "capget",
    "capset",
    "capable",
    "quotactl",
    "quota_on",
    "syslog",
    "settime",
    "vm_enough_memory",
    "bprm_creds_for_exec",
    "bprm_creds_from_file",
    "bprm_check_security",
    "bprm_committing_creds",
    "bprm_committed_creds",
    "fs_context_submount",
    "fs_context_dup",
    "fs_context_parse_param",
    "sb_alloc_security",
    "sb_delete",
    "sb_free_security",
    "sb_free_mnt_opts",
    "sb_eat_lsm_opts",
    "sb_mnt_opts_compat",
    "sb_remount",
    "sb_kern_mount",
    "sb_show_options",
    "sb_statfs",
    "sb_mount",
    "sb_umount",
    "sb_pivotroot",
    "sb_set_mnt_opts",
    "sb_clone_mnt_opts",
    "move_mount",
    "dentry_init_security",
    "dentry_create_files_as",
    "path_unlink",
    "path_mkdir",
    "path_rmdir",
    "path_mknod",
    "path_post_mknod",
    "path_truncate",
    "path_symlink",
    "path_link",
    "path_rename",
    "path_chmod",
    "path_chown",
    "path_chroot",
    "path_notify",
    "inode_alloc_security",
    "inode_free_security",
    "inode_free_security_rcu",
    "inode_init_security",
    "inode_init_security_anon",
    "inode_create",
    "inode_post_create_tmpfile",
    "inode_link",
    "inode_unlink",
    "inode_symlink",
    "inode_mkdir",
    "inode_rmdir",
    "inode_mknod",
    "inode_rename",
    "inode_readlink",
    "inode_follow_link",
    "inode_permission",
    "inode_setattr",
    "inode_post_setattr",
    "inode_getattr",
    "inode_xattr_skipcap",
    "inode_setxattr",
    "inode_post_setxattr",
    "inode_getxattr",
    "inode_listxattr",
    "inode_removexattr",
    "inode_post_removexattr",
    "inode_file_setattr",
    "inode_file_getattr",
    "inode_set_acl",
    "inode_post_set_acl",
    "inode_get_acl",
    "inode_remove_acl",
    "inode_post_remove_acl",
    "inode_need_killpriv",
    "inode_killpriv",
    "inode_getsecurity",
    "inode_setsecurity",
    "inode_listsecurity",
    "inode_getlsmprop",
    "inode_copy_up",
    "inode_copy_up_xattr",
    "inode_setintegrity",
    "kernfs_init_security",
    "file_permission",
    "file_alloc_security",
    "file_release",
    "file_free_security",
    "backing_file_alloc",
    "backing_file_free",
    "file_ioctl",
    "file_ioctl_compat",
    "mmap_addr",
    "mmap_file",
    "mmap_backing_file",
    "file_mprotect",
    "file_lock",
    "file_fcntl",
    "file_set_fowner",
    "file_send_sigiotask",
    "file_receive",
    "file_open",
    "file_post_open",
    "file_truncate",
    "task_alloc",
    "task_free",
    "cred_alloc_blank",
    "cred_free",
    "cred_prepare",
    "cred_transfer",
    "cred_getsecid",
    "cred_getlsmprop",
    "kernel_act_as",
    "kernel_create_files_as",
    "kernel_module_request",
    "kernel_load_data",
    "kernel_post_load_data",
    "kernel_read_file",
    "kernel_post_read_file",
    "task_fix_setuid",
    "task_fix_setgid",
    "task_fix_setgroups",
    "task_setpgid",
    "task_getpgid",
    "task_getsid",
    "current_getlsmprop_subj",
    "task_getlsmprop_obj",
    "task_setnice",
    "task_setioprio",
    "task_getioprio",
    "task_prlimit",
    "task_setrlimit",
    "task_setscheduler",
    "task_getscheduler",
    "task_movememory",
    "task_kill",
    "task_prctl",
    "task_to_inode",
    "userns_create",
    "namespace_init",
    "namespace_free",
    "namespace_install",
    "ipc_permission",
    "ipc_getlsmprop",
    "msg_msg_alloc_security",
    "msg_msg_free_security",
    "msg_queue_alloc_security",
    "msg_queue_free_security",
    "msg_queue_associate",
    "msg_queue_msgctl",
    "msg_queue_msgsnd",
    "msg_queue_msgrcv",
    "shm_alloc_security",
    "shm_free_security",
    "shm_associate",
    "shm_shmctl",
    "shm_shmat",
    "sem_alloc_security",
    "sem_free_security",
    "sem_associate",
    "sem_semctl",
    "sem_semop",
    "netlink_send",
    "d_instantiate",
    "getselfattr",
    "setselfattr",
    "getprocattr",
    "setprocattr",
    "ismaclabel",
    "secid_to_secctx",
    "lsmprop_to_secctx",
    "secctx_to_secid",
    "release_secctx",
    "inode_invalidate_secctx",
    "inode_notifysecctx",
    "inode_setsecctx",
    "inode_getsecctx",
    "post_notification",
    "watch_key",
    "unix_find",
    "unix_stream_connect",
    "unix_may_send",
    "socket_create",
    "socket_post_create",
    "socket_socketpair",
    "socket_bind",
    "socket_connect",
    "socket_listen",
    "socket_accept",
    "socket_sendmsg",
    "socket_recvmsg",
    "socket_getsockname",
    "socket_getpeername",
    "socket_getsockopt",
    "socket_setsockopt",
    "socket_shutdown",
    "socket_sock_rcv_skb",
    "socket_getpeersec_stream",
    "socket_getpeersec_dgram",
    "sk_alloc_security",
    "sk_free_security",
    "sk_clone_security",
    "sk_getsecid",
    "sock_graft",
    "inet_conn_request",
    "inet_csk_clone",
    "inet_conn_established",
    "secmark_relabel_packet",
    "secmark_refcount_inc",
    "secmark_refcount_dec",
    "req_classify_flow",
    "tun_dev_alloc_security",
    "tun_dev_create",
    "tun_dev_attach_queue",
    "tun_dev_attach",
    "tun_dev_open",
    "sctp_assoc_request",
    "sctp_bind_connect",
    "sctp_sk_clone",
    "sctp_assoc_established",
    "mptcp_add_subflow",
    "ib_pkey_access",
    "ib_endport_manage_subnet",
    "ib_alloc_security",
    "xfrm_policy_alloc_security",
    "xfrm_policy_clone_security",
    "xfrm_policy_free_security",
    "xfrm_policy_delete_security",
    "xfrm_state_alloc",
    "xfrm_state_alloc_acquire",
    "xfrm_state_free_security",
    "xfrm_state_delete_security",
    "xfrm_policy_lookup",
    "xfrm_state_pol_flow_match",
    "xfrm_decode_session",
    "key_alloc",
    "key_permission",
    "key_getsecurity",
    "key_post_create_or_update",
    "audit_rule_init",
    "audit_rule_known",
    "audit_rule_match",
    "audit_rule_free",
    "bpf",
    "bpf_map",
    "bpf_prog",
    "bpf_map_create",
    "bpf_map_free",
    "bpf_prog_load",
    "bpf_prog_free",
    "bpf_token_create",
    "bpf_token_free",
    "bpf_token_cmd",
    "bpf_token_capable",
    "locked_down",
    "perf_event_open",
    "perf_event_alloc",
    "perf_event_read",
    "perf_event_write",
    "uring_override_creds",
    "uring_sqpoll",
    "uring_cmd",
    "uring_allowed",
    "initramfs_populated",
    "bdev_alloc_security",
    "bdev_free_security",
    "bdev_setintegrity",
];

/// The count of the LSM hooks of Linux.
pub const HOOK_COUNT: usize = 280;

/// The index of the hook `name` in [`HOOK_NAMES`], or `None` if Linux has no hook with the name.
pub fn hook_index(name: &str) -> Option<usize> {
    HOOK_NAMES.iter().position(|n| *n == name)
}

/// The hooks of one LSM. Each method has the name of the hook of Linux. A method that gives an
/// error stops the operation, and the framework gives the first error, as `call_int_hook` of
/// Linux. The methods without a result are the hooks of `call_void_hook`.
#[allow(unused_variables)]
pub trait SecurityHooks: Sync {
    /// `capable`: the task with `cred` uses the capability `cap`. `opts` has the `CAP_OPT_*`
    /// bits.
    fn capable(&self, cred: &Cred, cap: u32, opts: u32) -> Result<()> {
        Ok(())
    }

    /// `capget`: the caller reads the capabilities of `target`.
    fn capget(&self, target: &Task<'_>) -> Result<()> {
        Ok(())
    }

    /// `capset`: the caller changes its capabilities from `old` to `new`.
    fn capset(&self, new: &Cred, old: &Cred) -> Result<()> {
        Ok(())
    }

    /// `ptrace_access_check`: the caller with `cred` traces or examines `child`. `mode` has the
    /// `PTRACE_MODE_*` bits.
    fn ptrace_access_check(&self, cred: &Cred, child: &Task<'_>, mode: u32) -> Result<()> {
        Ok(())
    }

    /// `ptrace_traceme`: `parent` becomes the tracer of the caller.
    fn ptrace_traceme(&self, parent: &Task<'_>) -> Result<()> {
        Ok(())
    }

    /// `bprm_creds_for_exec`: the new credentials of an `execve` are made.
    fn bprm_creds_for_exec(&self, bprm: &mut Bprm<'_>) -> Result<()> {
        Ok(())
    }

    /// `bprm_creds_from_file`: the credentials change for the file of `bprm`.
    fn bprm_creds_from_file(&self, bprm: &mut Bprm<'_>) -> Result<()> {
        Ok(())
    }

    /// `bprm_check_security`: the last check before the kernel loads the program.
    fn bprm_check_security(&self, bprm: &mut Bprm<'_>) -> Result<()> {
        Ok(())
    }

    /// `bprm_committing_creds`: the process gets the new credentials now.
    fn bprm_committing_creds(&self, bprm: &Bprm<'_>) {}

    /// `bprm_committed_creds`: the process has the new credentials, which are now the current
    /// credentials. `filename` and `file` are the program, as in [`Bprm`].
    fn bprm_committed_creds(&self, filename: &[u8], file: &Location) {}

    /// `sb_alloc_security`: the super block of the file system `dev` has a new blob.
    fn sb_alloc_security(&self, dev: u64, blob: &Blob) {}

    /// `sb_free_security`: the super block of the file system `dev` goes away.
    fn sb_free_security(&self, dev: u64, blob: &Blob) {}

    /// `inode_alloc_security`: `inode` has a new blob.
    fn inode_alloc_security(&self, inode: &dyn Inode, blob: &Blob) {}

    /// `d_instantiate`: a dentry gets `inode`.
    fn d_instantiate(&self, inode: &dyn Inode) {}

    /// `inode_permission`: the access `mask` (the `MAY_*` bits) to `inode`, after the checks of
    /// the mode and the ACL.
    fn inode_permission(&self, cred: &Cred, inode: &dyn Inode, mask: u32) -> Result<()> {
        Ok(())
    }

    /// `file_permission`: a read or a write of `file`. `mask` is `MAY_READ` or `MAY_WRITE`.
    fn file_permission(&self, file: &File, mask: u32) -> Result<()> {
        Ok(())
    }

    /// `file_alloc_security`: `file` is made. The blob of the file is `file.security()`.
    /// rukernel makes a file in places where it cannot fail, so this hook gives no error. A
    /// module that denies the open does it in `file_open`.
    fn file_alloc_security(&self, file: &File) {}

    /// `file_free_security`: `file` goes away.
    fn file_free_security(&self, file: &File) {}

    /// `file_ioctl`: the `ioctl` `cmd` on `file`.
    fn file_ioctl(&self, file: &File, cmd: u32, arg: u64) -> Result<()> {
        Ok(())
    }

    /// `mmap_file`: a map of `file`, or of anonymous memory if `file` is `None`. `reqprot` is the
    /// protection that the caller asks for and `prot` the protection that the kernel uses.
    fn mmap_file(&self, file: Option<&File>, reqprot: u64, prot: u64, flags: u64) -> Result<()> {
        Ok(())
    }

    /// `file_mprotect`: a change of the protection of a map of `file`, or of anonymous memory.
    fn file_mprotect(&self, file: Option<&File>, reqprot: u64, prot: u64) -> Result<()> {
        Ok(())
    }

    /// `file_lock`: a `flock` of `file`. `cmd` is the `LOCK_*` operation.
    fn file_lock(&self, file: &File, cmd: u32) -> Result<()> {
        Ok(())
    }

    /// `file_fcntl`: the `fcntl` `cmd` on `file`.
    fn file_fcntl(&self, file: &File, cmd: u32, arg: u64) -> Result<()> {
        Ok(())
    }

    /// `file_open`: `file` is opened, after the permission checks of the VFS. `flags` are the
    /// flags of the open call, with `O_CREAT` and `O_TRUNC`, as `f_flags` in `do_dentry_open`
    /// of Linux.
    fn file_open(&self, file: &File, cred: &Cred, flags: u32) -> Result<()> {
        Ok(())
    }

    /// `path_unlink`: `unlink` of the file `at` in the directory `dir`.
    fn path_unlink(&self, dir: &Location, at: &Location) -> Result<()> {
        Ok(())
    }

    /// `path_mkdir`: `mkdir` of the new directory `name` in `dir` with the mode `mode`.
    fn path_mkdir(&self, dir: &Location, name: &[u8], mode: u32) -> Result<()> {
        Ok(())
    }

    /// `path_rmdir`: `rmdir` of the directory `at` in the directory `dir`.
    fn path_rmdir(&self, dir: &Location, at: &Location) -> Result<()> {
        Ok(())
    }

    /// `path_mknod`: `mknod` of the new file `name` in `dir` with the mode `mode`, with the
    /// file type, and the device `dev`.
    fn path_mknod(&self, dir: &Location, name: &[u8], mode: u32, dev: u64) -> Result<()> {
        Ok(())
    }

    /// `path_truncate`: `truncate` of the file `at`.
    fn path_truncate(&self, at: &Location) -> Result<()> {
        Ok(())
    }

    /// `path_symlink`: `symlink` of the new link `name` in `dir` to `target`.
    fn path_symlink(&self, dir: &Location, name: &[u8], target: &[u8]) -> Result<()> {
        Ok(())
    }

    /// `path_link`: `link` of the file `old` to the new name `name` in `dir`.
    fn path_link(&self, old: &Location, dir: &Location, name: &[u8]) -> Result<()> {
        Ok(())
    }

    /// `path_rename`: `rename` of the file `old` to the name `name` in `dir`. `new` is the file
    /// that has the name now, if there is one. `flags` are the flags of `renameat2`.
    fn path_rename(
        &self,
        old: &Location,
        dir: &Location,
        name: &[u8],
        new: Option<&Location>,
        flags: u32,
    ) -> Result<()> {
        Ok(())
    }

    /// `path_chmod`: `chmod` of the file `at` to the mode `mode`.
    fn path_chmod(&self, at: &Location, mode: u32) -> Result<()> {
        Ok(())
    }

    /// `path_chown`: `chown` of the file `at` to the user `uid` and the group `gid`. `None`
    /// keeps the ID.
    fn path_chown(&self, at: &Location, uid: Option<u32>, gid: Option<u32>) -> Result<()> {
        Ok(())
    }

    /// `inode_getattr`: `stat` of the file `at`.
    fn inode_getattr(&self, at: &Location) -> Result<()> {
        Ok(())
    }

    /// `file_truncate`: `ftruncate` of `file`.
    fn file_truncate(&self, file: &File) -> Result<()> {
        Ok(())
    }

    /// `task_alloc`: `child` is made by `clone` with `clone_flags`. `child.security` is the new
    /// task blob, and it has a copy of the blob of the parent.
    fn task_alloc(&self, child: &Task<'_>, clone_flags: u64) -> Result<()> {
        Ok(())
    }

    /// `task_free`: the task with the blob `blob` goes away.
    fn task_free(&self, blob: &Blob) {}

    /// `task_fix_setuid`: the user IDs change from `old` to `new`. `flags` is the `LSM_SETID_*`
    /// value of the call.
    fn task_fix_setuid(&self, new: &mut Cred, old: &Cred, flags: u32) -> Result<()> {
        Ok(())
    }

    /// `task_fix_setgid`: the group IDs change from `old` to `new`.
    fn task_fix_setgid(&self, new: &mut Cred, old: &Cred, flags: u32) -> Result<()> {
        Ok(())
    }

    /// `task_fix_setgroups`: the supplementary groups change.
    fn task_fix_setgroups(&self, new: &mut Cred, old: &Cred) -> Result<()> {
        Ok(())
    }

    /// `task_setpgid`: the process group of `target` becomes `pgid`.
    fn task_setpgid(&self, target: &Task<'_>, pgid: u32) -> Result<()> {
        Ok(())
    }

    /// `task_getpgid`: the caller reads the process group of `target`.
    fn task_getpgid(&self, target: &Task<'_>) -> Result<()> {
        Ok(())
    }

    /// `task_getsid`: the caller reads the session of `target`.
    fn task_getsid(&self, target: &Task<'_>) -> Result<()> {
        Ok(())
    }

    /// `task_setnice`: the nice value of `target` becomes `nice`.
    fn task_setnice(&self, target: &Task<'_>, nice: i32) -> Result<()> {
        Ok(())
    }

    /// `task_setioprio`: the I/O priority of `target` becomes `ioprio`.
    fn task_setioprio(&self, target: &Task<'_>, ioprio: i32) -> Result<()> {
        Ok(())
    }

    /// `task_getioprio`: the caller reads the I/O priority of `target`.
    fn task_getioprio(&self, target: &Task<'_>) -> Result<()> {
        Ok(())
    }

    /// `task_prlimit`: the caller with `cred` reads or changes the limits of the task with
    /// `tcred`. `flags` has `LSM_PRLIMIT_READ` and `LSM_PRLIMIT_WRITE`.
    fn task_prlimit(&self, cred: &Cred, tcred: &Cred, flags: u32) -> Result<()> {
        Ok(())
    }

    /// `task_setscheduler`: the caller changes the scheduling policy of `target`.
    fn task_setscheduler(&self, target: &Task<'_>) -> Result<()> {
        Ok(())
    }

    /// `task_getscheduler`: the caller reads the scheduling policy of `target`.
    fn task_getscheduler(&self, target: &Task<'_>) -> Result<()> {
        Ok(())
    }

    /// `task_kill`: the caller with `cred` sends the signal `sig` to `target`.
    fn task_kill(&self, target: &Task<'_>, sig: u32, cred: &Cred) -> Result<()> {
        Ok(())
    }

    /// `userns_create`: the task with the credentials `cred` makes a user namespace. `new` are
    /// its credentials in the namespace. The module can change the part of `new` in the blob.
    fn userns_create(&self, cred: &Cred, new: &Cred) -> Result<()> {
        Ok(())
    }

    /// `task_prctl`: the caller calls `prctl(option, args...)`. A module that does not handle
    /// the option gives `None`, as `-ENOSYS` of Linux.
    fn task_prctl(&self, option: u32, args: [u64; 4]) -> Option<Result<u64>> {
        None
    }

    /// `socket_create`: the caller makes a socket. `kern` is true for a socket of the kernel.
    fn socket_create(&self, family: u32, kind: u32, protocol: u32, kern: bool) -> Result<()> {
        Ok(())
    }

    /// `socket_post_create`: the socket `sock` is made.
    fn socket_post_create(&self, sock: &Sock<'_>, kern: bool) -> Result<()> {
        Ok(())
    }

    /// `socket_socketpair`: `a` and `b` are a new pair.
    fn socket_socketpair(&self, a: &Sock<'_>, b: &Sock<'_>) -> Result<()> {
        Ok(())
    }

    /// `socket_bind`: `sock` gets the address `addr`.
    fn socket_bind(&self, sock: &Sock<'_>, addr: &[u8]) -> Result<()> {
        Ok(())
    }

    /// `socket_connect`: `sock` connects to `addr`.
    fn socket_connect(&self, sock: &Sock<'_>, addr: &[u8]) -> Result<()> {
        Ok(())
    }

    /// `socket_listen`: `sock` waits for connections.
    fn socket_listen(&self, sock: &Sock<'_>, backlog: i32) -> Result<()> {
        Ok(())
    }

    /// `socket_accept`: the caller takes a connection from `sock`.
    fn socket_accept(&self, sock: &Sock<'_>) -> Result<()> {
        Ok(())
    }

    /// `socket_sendmsg`: the caller sends `len` bytes on `sock` to `addr`, with the `MSG_*`
    /// bits `flags`.
    fn socket_sendmsg(
        &self,
        sock: &Sock<'_>,
        addr: Option<&[u8]>,
        flags: u32,
        len: usize,
    ) -> Result<()> {
        Ok(())
    }

    /// `socket_recvmsg`: the caller receives at most `len` bytes from `sock`.
    fn socket_recvmsg(&self, sock: &Sock<'_>, len: usize, flags: u32) -> Result<()> {
        Ok(())
    }

    /// `socket_getsockname`: the caller reads the local address of `sock`.
    fn socket_getsockname(&self, sock: &Sock<'_>) -> Result<()> {
        Ok(())
    }

    /// `socket_getpeername`: the caller reads the peer address of `sock`.
    fn socket_getpeername(&self, sock: &Sock<'_>) -> Result<()> {
        Ok(())
    }

    /// `socket_getsockopt`: the caller reads the option `name` at the level `level`.
    fn socket_getsockopt(&self, sock: &Sock<'_>, level: i32, name: i32) -> Result<()> {
        Ok(())
    }

    /// `socket_setsockopt`: the caller changes the option `name` at the level `level`.
    fn socket_setsockopt(&self, sock: &Sock<'_>, level: i32, name: i32) -> Result<()> {
        Ok(())
    }

    /// `socket_shutdown`: the caller stops a direction of `sock`. `how` is `SHUT_*`.
    fn socket_shutdown(&self, sock: &Sock<'_>, how: i32) -> Result<()> {
        Ok(())
    }

    /// `ipc_permission`: the access `flag` (the permission bits, as 0o444 for a read) to the
    /// System V IPC object `ipc`, after the check of the mode.
    fn ipc_permission(&self, cred: &Cred, ipc: &IpcOwner<'_>, flag: u32) -> Result<()> {
        Ok(())
    }

    /// `msg_queue_alloc_security`: a new message queue.
    fn msg_queue_alloc_security(&self, ipc: &IpcSecurity) -> Result<()> {
        Ok(())
    }

    /// `msg_queue_free_security`: a message queue goes away.
    fn msg_queue_free_security(&self, ipc: &IpcSecurity) {}

    /// `msg_queue_associate`: `msgget` finds the queue `ipc` by its key, with the flags `msqflg`.
    fn msg_queue_associate(&self, ipc: &IpcOwner<'_>, msqflg: u32) -> Result<()> {
        Ok(())
    }

    /// `sem_alloc_security`: a new semaphore set.
    fn sem_alloc_security(&self, ipc: &IpcSecurity) -> Result<()> {
        Ok(())
    }

    /// `sem_free_security`: a semaphore set goes away.
    fn sem_free_security(&self, ipc: &IpcSecurity) {}

    /// `sem_associate`: `semget` finds the set `ipc` by its key, with the flags `semflg`.
    fn sem_associate(&self, ipc: &IpcOwner<'_>, semflg: u32) -> Result<()> {
        Ok(())
    }

    /// `shm_alloc_security`: a new shared memory segment.
    fn shm_alloc_security(&self, ipc: &IpcSecurity) -> Result<()> {
        Ok(())
    }

    /// `shm_free_security`: a shared memory segment goes away.
    fn shm_free_security(&self, ipc: &IpcSecurity) {}

    /// `shm_associate`: `shmget` finds the segment `ipc` by its key, with the flags `shmflg`.
    fn shm_associate(&self, ipc: &IpcOwner<'_>, shmflg: u32) -> Result<()> {
        Ok(())
    }

    /// `getselfattr`: the context of the attribute `attr` (an `LSM_ATTR_*` value) of `task`, for
    /// `lsm_get_self_attr`. `EOPNOTSUPP` tells that the module does not have the attribute.
    fn getselfattr(&self, attr: u64, task: &Task<'_>) -> Result<Vec<u8>> {
        Err(rk_abi::Errno::EOPNOTSUPP)
    }

    /// `setselfattr`: sets the attribute `attr` of the caller to the context `ctx`, for
    /// `lsm_set_self_attr`. `flags` are the flags of the `struct lsm_ctx`.
    fn setselfattr(&self, attr: u64, ctx: &[u8], flags: u64) -> Result<()> {
        Err(rk_abi::Errno::EOPNOTSUPP)
    }

    /// `getprocattr`: the text of the attribute `name` of `task`, for a read of
    /// `/proc/PID/attr/NAME`. `None` tells that the module does not have the hook, so the next
    /// module gets the call.
    fn getprocattr(&self, task: &Task<'_>, name: &str) -> Option<Result<Vec<u8>>> {
        None
    }

    /// `setprocattr`: a write of `value` to `/proc/self/attr/NAME`. It gives the count of bytes
    /// that the module took. `None` is as for [`Self::getprocattr`].
    fn setprocattr(&self, name: &str, value: &[u8]) -> Option<Result<usize>> {
        None
    }
}
