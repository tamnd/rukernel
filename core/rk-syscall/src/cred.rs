//! The calls of the credentials: the user and group IDs, the supplementary groups and the
//! capabilities. The rules are in `rk_vfs::cred`.

use crate::cx::{Cx, SysResult};
use alloc::sync::Arc;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_vfs::cred::{Cred, NGROUPS_MAX, cap, secure, valid_cap};

/// The `option` values of `prctl` for the capabilities.
const PR_GET_KEEPCAPS: u64 = 7;
const PR_SET_KEEPCAPS: u64 = 8;
const PR_CAPBSET_READ: u64 = 23;
const PR_CAPBSET_DROP: u64 = 24;
const PR_GET_SECUREBITS: u64 = 27;
const PR_SET_SECUREBITS: u64 = 28;
const PR_CAP_AMBIENT: u64 = 47;

/// The operations of `PR_CAP_AMBIENT`.
const PR_CAP_AMBIENT_IS_SET: u64 = 1;
const PR_CAP_AMBIENT_RAISE: u64 = 2;
const PR_CAP_AMBIENT_LOWER: u64 = 3;
const PR_CAP_AMBIENT_CLEAR_ALL: u64 = 4;

/// The versions of the header of `capget` and `capset`. Version 1 has one set of 32 bits, and
/// versions 2 and 3 have two sets.
const LINUX_CAPABILITY_VERSION_1: u32 = 0x1998_0330;
const LINUX_CAPABILITY_VERSION_2: u32 = 0x2007_1026;
const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

/// Gives the credentials of the caller.
fn cred(cx: &Cx<'_>) -> Arc<Cred> {
    cx.process().cred()
}

/// An ID from an argument. The calls take a 32-bit ID, and -1 means no change.
fn id(arg: u64) -> u32 {
    arg as u32
}

/// `getuid`, `geteuid`, `getgid` and `getegid`.
pub(crate) fn getuid(cx: &Cx<'_>) -> SysResult {
    Ok(u64::from(cred(cx).uid))
}

pub(crate) fn geteuid(cx: &Cx<'_>) -> SysResult {
    Ok(u64::from(cred(cx).euid))
}

pub(crate) fn getgid(cx: &Cx<'_>) -> SysResult {
    Ok(u64::from(cred(cx).gid))
}

pub(crate) fn getegid(cx: &Cx<'_>) -> SysResult {
    Ok(u64::from(cred(cx).egid))
}

/// `getresuid` and `getresgid`.
pub(crate) fn getresid(cx: &Cx<'_>, group: bool, r: u64, e: u64, s: u64) -> SysResult {
    let c = cred(cx);
    let ids = if group { [c.gid, c.egid, c.sgid] } else { [c.uid, c.euid, c.suid] };
    for (addr, id) in [r, e, s].into_iter().zip(ids) {
        cx.write_val(addr, &id)?;
    }
    Ok(0)
}

/// Changes the credentials of the caller with `f`.
fn change(cx: &Cx<'_>, f: impl FnOnce(&Cred) -> Result<Cred, Errno>) -> SysResult {
    cx.process().change_cred(f).map(|()| 0)
}

pub(crate) fn setuid(cx: &Cx<'_>, uid: u64) -> SysResult {
    change(cx, |c| c.setuid(id(uid)))
}

pub(crate) fn setreuid(cx: &Cx<'_>, ruid: u64, euid: u64) -> SysResult {
    change(cx, |c| c.setreuid(id(ruid), id(euid)))
}

pub(crate) fn setresuid(cx: &Cx<'_>, ruid: u64, euid: u64, suid: u64) -> SysResult {
    change(cx, |c| c.setresuid(id(ruid), id(euid), id(suid)))
}

pub(crate) fn setgid(cx: &Cx<'_>, gid: u64) -> SysResult {
    change(cx, |c| c.setgid(id(gid)))
}

pub(crate) fn setregid(cx: &Cx<'_>, rgid: u64, egid: u64) -> SysResult {
    change(cx, |c| c.setregid(id(rgid), id(egid)))
}

pub(crate) fn setresgid(cx: &Cx<'_>, rgid: u64, egid: u64, sgid: u64) -> SysResult {
    change(cx, |c| c.setresgid(id(rgid), id(egid), id(sgid)))
}

/// `setfsuid` and `setfsgid` give the old ID, also when they change nothing.
pub(crate) fn setfsuid(cx: &Cx<'_>, uid: u64) -> SysResult {
    let mut old = 0;
    let _ = cx.process().change_cred(|c| {
        old = c.fsuid;
        c.setfsuid(id(uid)).ok_or(Errno::EPERM)
    });
    Ok(u64::from(old))
}

pub(crate) fn setfsgid(cx: &Cx<'_>, gid: u64) -> SysResult {
    let mut old = 0;
    let _ = cx.process().change_cred(|c| {
        old = c.fsgid;
        c.setfsgid(id(gid)).ok_or(Errno::EPERM)
    });
    Ok(u64::from(old))
}

/// `getgroups`. A size of 0 gives the number of groups and writes nothing.
pub(crate) fn getgroups(cx: &Cx<'_>, size: u64, list: u64) -> SysResult {
    let c = cred(cx);
    let n = c.groups.len();
    let size = size as i32;
    if size < 0 {
        return Err(Errno::EINVAL);
    }
    if size == 0 {
        return Ok(n as u64);
    }
    if (size as usize) < n {
        return Err(Errno::EINVAL);
    }
    let bytes: Vec<u8> = c.groups.iter().flat_map(|g| g.to_ne_bytes()).collect();
    cx.write_bytes(list, &bytes)?;
    Ok(n as u64)
}

/// `setgroups`.
pub(crate) fn setgroups(cx: &Cx<'_>, size: u64, list: u64) -> SysResult {
    let size = size as i32;
    if size < 0 || size as usize > NGROUPS_MAX {
        return Err(Errno::EINVAL);
    }
    let bytes = cx.read_bytes(list, 4 * size as usize)?;
    let groups = bytes.as_chunks::<4>().0.iter().map(|b| u32::from_ne_bytes(*b)).collect();
    change(cx, |c| c.setgroups(groups))
}

/// Reads the header of `capget` and `capset`, and gives the number of 32-bit sets of the
/// version and the process ID. An unknown version writes version 3 into the header, as
/// `cap_validate_magic` of Linux does.
fn cap_header(cx: &Cx<'_>, header: u64) -> Result<(usize, i32), Errno> {
    let [version, pid]: [u32; 2] = cx.read_val(header)?;
    let sets = match version {
        LINUX_CAPABILITY_VERSION_1 => 1,
        LINUX_CAPABILITY_VERSION_2 | LINUX_CAPABILITY_VERSION_3 => 2,
        _ => {
            cx.write_val(header, &LINUX_CAPABILITY_VERSION_3)?;
            return Err(Errno::EINVAL);
        }
    };
    Ok((sets, pid as i32))
}

/// `capget`.
pub(crate) fn capget(cx: &Cx<'_>, header: u64, data: u64) -> SysResult {
    let (sets, pid) = match cap_header(cx, header) {
        Err(Errno::EINVAL) if data == 0 => return Ok(0),
        r => r?,
    };
    if data == 0 {
        return Ok(0);
    }
    if pid < 0 {
        return Err(Errno::EINVAL);
    }
    let c = if pid == 0 {
        cred(cx)
    } else {
        rk_proc::find_thread(pid as rk_proc::Pid).ok_or(Errno::ESRCH)?.process().cred()
    };
    let mut out = [0u32; 6];
    for (i, set) in out.chunks_mut(3).take(sets).enumerate() {
        let part = |bits: u64| (bits >> (32 * i)) as u32;
        set.copy_from_slice(&[
            part(c.cap_effective),
            part(c.cap_permitted),
            part(c.cap_inheritable),
        ]);
    }
    let bytes: Vec<u8> = out[..3 * sets].iter().flat_map(|w| w.to_ne_bytes()).collect();
    cx.write_bytes(data, &bytes)?;
    Ok(0)
}

/// `capset`. A process can only change its own sets.
pub(crate) fn capset(cx: &Cx<'_>, header: u64, data: u64) -> SysResult {
    let (sets, pid) = cap_header(cx, header)?;
    if pid != 0 && pid as u32 != cx.process().pid() {
        return Err(Errno::EPERM);
    }
    let bytes = cx.read_bytes(data, 12 * sets)?;
    let word = |i: usize| {
        u64::from(u32::from_ne_bytes([
            bytes[4 * i],
            bytes[4 * i + 1],
            bytes[4 * i + 2],
            bytes[4 * i + 3],
        ]))
    };
    let mut set = [0u64; 3];
    for s in 0..sets {
        for (k, bits) in set.iter_mut().enumerate() {
            *bits |= word(3 * s + k) << (32 * s);
        }
    }
    change(cx, |c| c.capset(set[0], set[1], set[2]))
}

/// The capability options of `prctl`, or `None` for another option.
pub(crate) fn prctl(cx: &Cx<'_>, option: u64, args: [u64; 4]) -> Option<SysResult> {
    let arg2 = args[0];
    Some(match option {
        PR_GET_KEEPCAPS => Ok(u64::from(cred(cx).securebits & secure::KEEP_CAPS != 0)),
        PR_SET_KEEPCAPS => change(cx, |c| c.set_keepcaps(arg2)),
        PR_CAPBSET_READ => valid_cap(arg2).map(|n| u64::from(cred(cx).cap_bset & cap::bit(n) != 0)),
        PR_CAPBSET_DROP => change(cx, |c| c.drop_bset(arg2)),
        PR_GET_SECUREBITS => Ok(u64::from(cred(cx).securebits)),
        PR_SET_SECUREBITS => change(cx, |c| c.set_securebits(arg2 as u32)),
        PR_CAP_AMBIENT => ambient(cx, args),
        _ => return None,
    })
}

/// `PR_CAP_AMBIENT`.
fn ambient(cx: &Cx<'_>, args: [u64; 4]) -> SysResult {
    let [op, c, a4, a5] = args;
    if op == PR_CAP_AMBIENT_CLEAR_ALL {
        if c != 0 || a4 != 0 || a5 != 0 {
            return Err(Errno::EINVAL);
        }
        return change(cx, |old| {
            let mut new = old.clone();
            new.cap_ambient = 0;
            Ok(new)
        });
    }
    if a4 != 0 || a5 != 0 {
        return Err(Errno::EINVAL);
    }
    match op {
        PR_CAP_AMBIENT_IS_SET => {
            valid_cap(c).map(|n| u64::from(cred(cx).cap_ambient & cap::bit(n) != 0))
        }
        PR_CAP_AMBIENT_RAISE => change(cx, |old| old.set_ambient(c, true)),
        PR_CAP_AMBIENT_LOWER => change(cx, |old| old.set_ambient(c, false)),
        _ => Err(Errno::EINVAL),
    }
}
