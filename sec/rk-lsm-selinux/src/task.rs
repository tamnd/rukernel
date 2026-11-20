//! The SIDs of the tasks, `struct task_security_struct` of security/selinux of Linux: the SID
//! of a task in its credentials, the change of the SID at an exec, and the attributes of
//! `/proc/PID/attr` and of `lsm_get_self_attr` and `lsm_set_self_attr`.

use crate::classmap::{class, file, key, process, process2};
use crate::sidtab::sid;
use crate::{avc, server, services};
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;
use rk_abi::Errno;
use rk_abi::native::mount::MS_NOSUID;
use rk_vfs::cred::{Cred, cap};
use rk_vfs::dentry::Location;
use rk_vfs::inode::Result;
use rk_vfs::security::{Bprm, Task, attr, id};

/// The size of the part of SELinux in the credentials blob: the six SIDs of [`slot`], one in
/// each word.
pub const CRED_BLOB: usize = 48;

/// The byte offsets of the SIDs in the part of SELinux in the credentials blob, the fields of
/// `struct task_security_struct` of Linux. 0 in [`slot::SID`] and [`slot::OSID`] is the SID
/// `kernel`, so the credentials of the kernel, which have a blob of zeros, have the SID of the
/// kernel, as `cred_init_security` of Linux. 0 in another slot is no SID.
pub mod slot {
    /// The SID of the task, `sid`.
    pub const SID: usize = 0;
    /// The SID before the last exec or change of the SID, `osid`.
    pub const OSID: usize = 8;
    /// The SID for the next exec, `exec_sid`.
    pub const EXEC: usize = 16;
    /// The SID of the new files, `create_sid`.
    pub const CREATE: usize = 24;
    /// The SID of the new keys, `keycreate_sid`.
    pub const KEYCREATE: usize = 32;
    /// The SID of the new sockets, `sockcreate_sid`.
    pub const SOCKCREATE: usize = 40;
}

/// The number of the policy capability `nnp_nosuid_transition` in
/// [`crate::POLICYCAP_NAMES`].
const POLICYCAP_NNP_NOSUID_TRANSITION: u32 = 5;

/// The byte offset of the part of SELinux in the credentials blob, or `None` if the module is
/// not active.
fn cred_offset() -> Option<usize> {
    rk_vfs::security::modules().iter().find(|m| m.info.id.id == id::SELINUX).map(|m| m.offsets.cred)
}

/// The SID at the byte offset `slot` of the part of SELinux in the blob of `cred`.
pub fn load(cred: &Cred, slot: usize) -> u32 {
    let v = cred_offset().map_or(0, |off| cred.security.load(off + slot)) as u32;
    if v == 0 && (slot == slot::SID || slot == slot::OSID) { sid::KERNEL } else { v }
}

/// Writes the SID at the byte offset `slot` of the part of SELinux in the blob of `cred`.
pub fn store(cred: &Cred, slot: usize, sid: u32) {
    if let Some(off) = cred_offset() {
        cred.security.store(off + slot, u64::from(sid));
    }
}

/// The SID of the task with the credentials `cred`, as `cred_sid` of Linux.
pub fn cred_sid(cred: &Cred) -> u32 {
    load(cred, slot::SID)
}

/// Checks the capability `cap` of the task with `cred`, as `cred_has_capability` of Linux:
/// the permission of the capability in the class `capability` or `capability2` on the task
/// itself, or in `cap_userns` or `cap2_userns` if the capability is not for the first user
/// namespace (`initns` false). The record has ` capability=N `.
///
/// # Errors
///
/// `EACCES` if the policy denies the permission in enforcing mode, and `EINVAL` for a
/// capability after the last one.
pub fn cred_has_capability(cred: &Cred, cap: u32, initns: bool) -> Result<()> {
    let sclass = match (cap / 32, initns) {
        (0, true) => class::CAPABILITY,
        (0, false) => class::CAP_USERNS,
        (1, true) => class::CAPABILITY2,
        (1, false) => class::CAP2_USERNS,
        _ => {
            rk_frame::println!("SELinux:  out of range capability {cap}");
            return Err(Errno::EINVAL);
        }
    };
    let sid = cred_sid(cred);
    avc::has_perm(sid, sid, sclass, 1 << (cap % 32), |s| {
        let _ = write!(s, " capability={cap} ");
    })
}

/// The SID of the file `at`, from [`crate::inode::inode_sid`].
fn file_sid(at: &Location) -> u32 {
    crate::inode::inode_sid(&**at.inode(), Some(at))
}

/// The SID of the task after the exec of `bprm`, as `selinux_bprm_creds_for_exec` of Linux.
/// The task gets the SID of `/proc/self/attr/exec`, or else the SID of a `type_transition`
/// rule for the file, or else keeps its SID. The new credentials have no SID for the next exec
/// and for the new files, keys and sockets. Before the first policy load, the task gets the
/// SID `init`. A change of the SID needs the permission `transition`, the file needs
/// `entrypoint` for the new SID, a tracer needs `ptrace` on the new SID, and without
/// `noatsecure` the program gets the secure mode of `AT_SECURE`. An exec without a change
/// needs `execute_no_trans` on the file.
///
/// Linux also checks `share` for a task that shares its state with another task and clears
/// the flags of the personality that a change of the SID makes unsafe. The exec of rukernel
/// does not tell the hooks these yet.
///
/// # Errors
///
/// `EACCES` if the policy denies a check, `EPERM` for the tracer and for a change with
/// `no_new_privs` that the policy does not allow, and the errors of
/// [`server::transition_sid`].
pub fn bprm_creds_for_exec(bprm: &mut Bprm<'_>) -> Result<()> {
    // The new credentials are a copy of the credentials of the task.
    let old = cred_sid(bprm.cred);
    let exec_sid = load(bprm.cred, slot::EXEC);
    store(bprm.cred, slot::OSID, old);
    for s in [slot::CREATE, slot::KEYCREATE, slot::SOCKCREATE] {
        store(bprm.cred, s, 0);
    }
    if !crate::initialized() {
        store(bprm.cred, slot::SID, sid::INIT);
        store(bprm.cred, slot::EXEC, 0);
        return Ok(());
    }
    let isid = file_sid(bprm.file);
    let new = if exec_sid != 0 {
        store(bprm.cred, slot::EXEC, 0);
        check_nnp_nosuid(bprm, old, exec_sid)?;
        exec_sid
    } else {
        let t = server::transition_sid(old, isid, class::PROCESS, None)?;
        // A change that `no_new_privs` or `nosuid` does not allow keeps the old SID.
        if check_nnp_nosuid(bprm, old, t).is_ok() { t } else { old }
    };
    store(bprm.cred, slot::SID, new);
    if new == old {
        return avc::has_perm(
            old,
            isid,
            class::FILE,
            file::EXECUTE_NO_TRANS,
            crate::file::path_fields(bprm.file),
        );
    }
    avc::has_perm(
        old,
        new,
        class::PROCESS,
        process::TRANSITION,
        crate::file::path_fields(bprm.file),
    )?;
    avc::has_perm(new, isid, class::FILE, file::ENTRYPOINT, crate::file::path_fields(bprm.file))?;
    if let Some(tracer) = bprm.tracer {
        avc::has_perm(cred_sid(tracer), new, class::PROCESS, process::PTRACE, |_| {})
            .map_err(|_| Errno::EPERM)?;
    }
    if avc::has_perm(old, new, class::PROCESS, process::NOATSECURE, |_| {}).is_err() {
        bprm.secureexec = true;
    }
    Ok(())
}

/// The check of a change of the SID from `old` to `new` at an exec with `no_new_privs` or
/// from a mount with `nosuid`, as `check_nnp_nosuid` of Linux. With the policy capability
/// `nnp_nosuid_transition`, the permissions `nnp_transition` and `nosuid_transition` of the
/// class `process2` allow the change. A change to a type that the old type bounds is allowed.
///
/// # Errors
///
/// `EPERM` with `no_new_privs`, else `EACCES`.
fn check_nnp_nosuid(bprm: &Bprm<'_>, old: u32, new: u32) -> Result<()> {
    let nnp = sys::no_new_privs();
    let nosuid = bprm.file.mount.flags() & u64::from(MS_NOSUID) != 0;
    if !nnp && !nosuid || new == old {
        return Ok(());
    }
    if crate::policy().is_some_and(|p| p.db.policycap(POLICYCAP_NNP_NOSUID_TRANSITION)) {
        let mut av = 0;
        if nnp {
            av |= process2::NNP_TRANSITION;
        }
        if nosuid {
            av |= process2::NOSUID_TRANSITION;
        }
        if avc::has_perm(old, new, class::PROCESS2, av, |_| {}).is_ok() {
            return Ok(());
        }
    }
    if server::bounded_transition(old, new).is_ok() {
        return Ok(());
    }
    Err(if nnp { Errno::EPERM } else { Errno::EACCES })
}

/// The slot of the attribute `attr`, an `LSM_ATTR_*` value.
fn slot_of(attr: u64) -> Option<usize> {
    Some(match attr {
        attr::CURRENT => slot::SID,
        attr::PREV => slot::OSID,
        attr::EXEC => slot::EXEC,
        attr::FSCREATE => slot::CREATE,
        attr::KEYCREATE => slot::KEYCREATE,
        attr::SOCKCREATE => slot::SOCKCREATE,
        _ => return None,
    })
}

/// The attribute with the name `name` of `/proc/PID/attr`, `lsm_name_to_attr` of Linux.
/// [`attr::UNDEF`] is a name that is not known.
fn attr_of_name(name: &str) -> u64 {
    match name {
        "current" => attr::CURRENT,
        "exec" => attr::EXEC,
        "fscreate" => attr::FSCREATE,
        "keycreate" => attr::KEYCREATE,
        "prev" => attr::PREV,
        "sockcreate" => attr::SOCKCREATE,
        _ => attr::UNDEF,
    }
}

/// The attribute `attr` of `task`, as `selinux_lsm_getattr` of Linux: the context of the SID
/// with a NUL at the end, or nothing for no SID. A read of another task needs the permission
/// `getattr` on it.
///
/// # Errors
///
/// `EACCES` if the policy denies `getattr`, `EOPNOTSUPP` for an attribute that SELinux does
/// not have, and `EINVAL` for a SID without a context.
pub fn getattr(attr: u64, task: &Task<'_>) -> Result<Vec<u8>> {
    if sys::tid() != Some(task.pid) {
        let tsid = cred_sid(task.cred);
        avc::has_perm(crate::current_sid(), tsid, class::PROCESS, process::GETATTR, |_| {})?;
    }
    let slot = slot_of(attr).ok_or(Errno::EOPNOTSUPP)?;
    let sid = load(task.cred, slot);
    if sid == 0 {
        return Ok(Vec::new());
    }
    let mut text = server::sid_to_context(sid)?.into_bytes();
    text.push(0);
    Ok(text)
}

/// A read of `/proc/PID/attr/NAME`, as `selinux_getprocattr` of Linux.
///
/// # Errors
///
/// As [`getattr`], and `EINVAL` for a name that SELinux does not have.
pub fn getprocattr(task: &Task<'_>, name: &str) -> Result<Vec<u8>> {
    match attr_of_name(name) {
        attr::UNDEF => Err(Errno::EINVAL),
        a => getattr(a, task).map_err(|e| if e == Errno::EOPNOTSUPP { Errno::EINVAL } else { e }),
    }
}

/// A write of `/proc/self/attr/NAME`, as `selinux_setprocattr` of Linux.
///
/// # Errors
///
/// As [`setattr`], and `EINVAL` for a name that SELinux does not have.
pub fn setprocattr(name: &str, value: &[u8]) -> Result<usize> {
    match attr_of_name(name) {
        attr::UNDEF => Err(Errno::EINVAL),
        a => setattr(a, value),
    }
}

/// Sets the attribute `attr` of the caller to the context in `value`, as
/// `selinux_lsm_setattr` of Linux. A change of each attribute needs its permission on the
/// task itself: `setexec`, `setfscreate`, `setkeycreate`, `setsockcreate` or `setcurrent`. The
/// context can end with a NUL or with a new line. An empty value, or a value that starts with
/// a NUL or a new line, clears the attribute.
///
/// A context for the new files that the policy does not know needs `CAP_MAC_ADMIN`. A new SID
/// for the next keys needs the permission `create` of the class `key` on it. A change of the
/// SID of the task needs a SID, a type that the old type bounds if the process has more than
/// one thread, the permission `dyntransition` to the new SID, and for a traced task the
/// permission `ptrace` of the tracer on it.
///
/// Gives the count of bytes that the module took. As on Linux, it does not count a new line
/// at the end.
///
/// # Errors
///
/// `EACCES` if the policy denies a check, `EINVAL` for a context that the policy does not
/// know and for no SID in `current`, `EPERM` for a type that the old type does not bound, and
/// `EOPNOTSUPP` for an attribute that the caller cannot set.
pub fn setattr(attr: u64, value: &[u8]) -> Result<usize> {
    let cred = rk_vfs::cred::current();
    let mysid = cred_sid(&cred);
    let perm = match attr {
        attr::EXEC => process::SETEXEC,
        attr::FSCREATE => process::SETFSCREATE,
        attr::KEYCREATE => process::SETKEYCREATE,
        attr::SOCKCREATE => process::SETSOCKCREATE,
        attr::CURRENT => process::SETCURRENT,
        _ => return Err(Errno::EOPNOTSUPP),
    };
    avc::has_perm(mysid, mysid, class::PROCESS, perm, |_| {})?;
    let mut size = value.len();
    let mut sid = 0;
    if value.first().is_some_and(|&c| c != 0 && c != b'\n') {
        if value[size - 1] == b'\n' {
            size -= 1;
        }
        let text = &value[..size];
        sid = match server::context_to_sid(text, 0, false) {
            Err(Errno::EINVAL) if attr == attr::FSCREATE => {
                if !cred.capable(cap::MAC_ADMIN) {
                    let mut s = String::from("op=fscreate invalid_context=");
                    avc::untrusted(&mut s, text.strip_suffix(&[0]).unwrap_or(text));
                    services::log_err(&s);
                    return Err(Errno::EINVAL);
                }
                server::context_to_sid(text, 0, true)?
            }
            r => r?,
        };
    }
    let new = (*cred).clone();
    match attr {
        attr::KEYCREATE if sid != 0 => {
            avc::has_perm(mysid, sid, class::KEY, key::CREATE, |_| {})?;
        }
        attr::CURRENT => {
            if sid == 0 {
                return Err(Errno::EINVAL);
            }
            if !sys::single_threaded() {
                server::bounded_transition(mysid, sid)?;
            }
            avc::has_perm(mysid, sid, class::PROCESS, process::DYNTRANSITION, |_| {})?;
            if let Some(tracer) = sys::tracer() {
                avc::has_perm(cred_sid(&tracer), sid, class::PROCESS, process::PTRACE, |_| {})?;
            }
            store(&new, slot::OSID, mysid);
        }
        _ => {}
    }
    store(&new, slot_of(attr).ok_or(Errno::EOPNOTSUPP)?, sid);
    sys::commit(new);
    Ok(size)
}

/// The state of the task that runs now.
#[cfg(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64")))]
mod sys {
    use alloc::sync::Arc;
    use rk_vfs::cred::Cred;

    /// The thread ID.
    pub(super) fn tid() -> Option<u32> {
        rk_proc::current_thread().map(|t| t.tid())
    }

    /// The task has `no_new_privs`, `LSM_UNSAFE_NO_NEW_PRIVS` of Linux.
    pub(super) fn no_new_privs() -> bool {
        rk_proc::current_thread().is_some_and(|t| t.no_new_privs())
    }

    /// The process has one thread, as `current_is_single_threaded` of Linux.
    pub(super) fn single_threaded() -> bool {
        rk_proc::current_thread().is_none_or(|t| t.process().threads().len() == 1)
    }

    /// The credentials of the tracer, as `ptrace_parent_sid` of Linux.
    pub(super) fn tracer() -> Option<Arc<Cred>> {
        rk_proc::current_thread().filter(|t| t.is_traced()).and_then(|t| t.tracer_cred())
    }

    /// Gives the caller the new credentials `new`, as `commit_creds` of Linux.
    pub(super) fn commit(new: Cred) {
        if let Some(t) = rk_proc::current_thread() {
            t.process().set_cred(new);
        }
    }
}

/// A build for the host has no task.
#[cfg(not(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64"))))]
mod sys {
    use alloc::sync::Arc;
    use rk_vfs::cred::Cred;

    pub(super) fn tid() -> Option<u32> {
        None
    }

    pub(super) fn no_new_privs() -> bool {
        false
    }

    pub(super) fn single_threaded() -> bool {
        true
    }

    pub(super) fn tracer() -> Option<Arc<Cred>> {
        None
    }

    pub(super) fn commit(_new: Cred) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TEST_LOCK;

    /// Makes SELinux the active module, so that the credentials have its part of the blob, and
    /// loads the policy rk_test.
    fn setup() -> std::sync::MutexGuard<'static, ()> {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            rk_vfs::security::register(&crate::LSM);
            rk_vfs::security::init(Some("selinux"), None);
        });
        let guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        crate::load_policy(include_bytes!("../tests/rk_test.35.bin")).unwrap();
        guard
    }

    fn sid_of(text: &str) -> u32 {
        server::context_to_sid(text.as_bytes(), 0, false).unwrap()
    }

    /// A file for an exec, in a mount of its own.
    fn exec_file() -> Location {
        let (r, _w) = rk_vfs::pipe::pipe(0);
        Location::detached(rk_vfs::pipe::pipe_inode(&r).unwrap())
    }

    fn exec(cred: &mut Cred, at: &Location) -> (Result<()>, bool) {
        let mut bprm = Bprm { filename: b"/x", file: at, cred, secureexec: false, tracer: None };
        let r = bprm_creds_for_exec(&mut bprm);
        (r, bprm.secureexec)
    }

    #[test]
    fn the_credentials_of_the_kernel_have_the_sid_kernel() {
        let _guard = setup();
        let cred = Cred::root();
        assert_eq!(cred_sid(&cred), sid::KERNEL);
        assert_eq!(load(&cred, slot::OSID), sid::KERNEL);
        assert_eq!(load(&cred, slot::EXEC), 0);
        store(&cred, slot::EXEC, 9);
        assert_eq!(load(&cred.clone(), slot::EXEC), 9);
        assert_eq!(
            crate::POLICYCAP_NAMES[POLICYCAP_NNP_NOSUID_TRANSITION as usize],
            "nnp_nosuid_transition"
        );
    }

    #[test]
    fn an_exec_takes_the_sid_for_the_next_exec() {
        let _guard = setup();
        let at = exec_file();
        let init = sid_of("system_u:system_r:init_t:s0");
        let mut cred = Cred::root();
        store(&cred, slot::EXEC, init);
        store(&cred, slot::CREATE, init);
        let (r, secure) = exec(&mut cred, &at);
        // Permissive mode: the denials of entrypoint and noatsecure do not fail the exec.
        assert_eq!(r, Ok(()));
        assert!(!secure);
        assert_eq!(cred_sid(&cred), init);
        assert_eq!(load(&cred, slot::OSID), sid::KERNEL);
        assert_eq!(load(&cred, slot::EXEC), 0);
        assert_eq!(load(&cred, slot::CREATE), 0);
        // Without a SID for the exec and without a rule, the SID stays.
        let (r, _) = exec(&mut cred, &at);
        assert_eq!(r, Ok(()));
        assert_eq!(cred_sid(&cred), init);
        assert_eq!(load(&cred, slot::OSID), init);
    }

    #[test]
    fn an_exec_in_enforcing_mode_needs_the_entrypoint() {
        let _guard = setup();
        let at = exec_file();
        let mut cred = Cred::root();
        store(&cred, slot::EXEC, sid_of("system_u:system_r:init_t:s0"));
        crate::set_enforcing(true);
        let (r, _) = exec(&mut cred, &at);
        let (plain, _) = exec(&mut Cred::root(), &at);
        crate::set_enforcing(false);
        // The rules allow the transition to init_t, but not the entrypoint on unlabeled_t.
        assert_eq!(r, Err(Errno::EACCES));
        // kernel_t has no execute_no_trans on unlabeled_t.
        assert_eq!(plain, Err(Errno::EACCES));
    }

    #[test]
    fn the_attributes_give_the_contexts_with_a_nul() {
        let _guard = setup();
        let cred = Cred::root();
        store(&cred, slot::CREATE, sid_of("system_u:object_r:etc_t:s0"));
        let task = Task { pid: 1, cred: &cred, security: None };
        let kernel = b"system_u:system_r:kernel_t:s0-s1:c0.c2\0";
        assert_eq!(getprocattr(&task, "current").unwrap(), kernel);
        assert_eq!(getprocattr(&task, "prev").unwrap(), kernel);
        assert_eq!(getprocattr(&task, "exec").unwrap(), b"");
        assert_eq!(getprocattr(&task, "fscreate").unwrap(), b"system_u:object_r:etc_t:s0\0");
        assert_eq!(getprocattr(&task, "none"), Err(Errno::EINVAL));
        assert_eq!(getattr(attr::CURRENT, &task).unwrap(), kernel);
        assert_eq!(getattr(attr::UNDEF, &task), Err(Errno::EOPNOTSUPP));
    }

    #[test]
    fn a_write_of_an_attribute_takes_a_context() {
        let _guard = setup();
        let ctx = b"system_u:system_r:init_t:s0";
        assert_eq!(setprocattr("exec", ctx), Ok(ctx.len()));
        assert_eq!(setprocattr("exec", b"system_u:system_r:init_t:s0\0"), Ok(ctx.len() + 1));
        // As on Linux, the new line at the end does not count.
        assert_eq!(setprocattr("exec", b"system_u:system_r:init_t:s0\n"), Ok(ctx.len()));
        assert_eq!(setprocattr("exec", b"\n"), Ok(1));
        assert_eq!(setprocattr("sockcreate", b""), Ok(0));
        assert_eq!(setprocattr("exec", b"system_u:system_r:nothing_t:s0"), Err(Errno::EINVAL));
        // The root of the host has CAP_MAC_ADMIN, so a context that the policy does not
        // know works for the new files.
        assert_eq!(setprocattr("fscreate", b"system_u:object_r:nothing_t:s0"), Ok(30));
        assert_eq!(setprocattr("current", b"\n"), Err(Errno::EINVAL));
        assert_eq!(setprocattr("current", ctx), Ok(ctx.len()));
        assert_eq!(setprocattr("keycreate", ctx), Ok(ctx.len()));
        assert_eq!(setprocattr("prev", ctx), Err(Errno::EOPNOTSUPP));
        assert_eq!(setprocattr("none", ctx), Err(Errno::EINVAL));
        crate::set_enforcing(true);
        let r = setprocattr("exec", ctx);
        crate::set_enforcing(false);
        // kernel_t has no setexec.
        assert_eq!(r, Err(Errno::EACCES));
    }

    #[test]
    fn a_change_to_another_type_needs_a_bound() {
        let _guard = setup();
        let kernel = sid::KERNEL;
        let init = sid_of("system_u:system_r:init_t:s0");
        assert_eq!(server::bounded_transition(kernel, kernel), Ok(()));
        assert_eq!(server::bounded_transition(kernel, init), Err(Errno::EPERM));
    }
}
