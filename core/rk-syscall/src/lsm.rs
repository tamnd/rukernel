//! The system calls of the security modules, as security/lsm_syscalls.c of Linux:
//! `lsm_get_self_attr`, `lsm_set_self_attr` and `lsm_list_modules`.

use crate::cx::{Cx, SysResult};
use rk_abi::Errno;
use rk_vfs::security::{self, LSM_CTX_HEADER, LSM_FLAG_SINGLE};

/// `lsm_get_self_attr(attr, ctx, size, flags)`: the attribute `attr` of the caller from each
/// module, as `struct lsm_ctx` entries in `ctx`. `*size` is the room of `ctx`, and the call sets
/// it to the size of all the entries. With `LSM_FLAG_SINGLE`, `ctx` has the ID of the module.
/// A `ctx` of 0 gives the size only. Gives the count of entries.
pub(crate) fn lsm_get_self_attr(
    cx: &Cx<'_>,
    attr: u64,
    ctx: u64,
    size: u64,
    flags: u64,
) -> SysResult {
    let (attr, flags) = (u64::from(attr as u32), flags as u32);
    if attr == security::attr::UNDEF || size == 0 {
        return Err(Errno::EINVAL);
    }
    let room: u32 = cx.read_val(size)?;
    let single = if flags != 0 {
        if flags != LSM_FLAG_SINGLE || ctx == 0 {
            return Err(Errno::EINVAL);
        }
        let id: u64 = cx.read_val(ctx)?;
        if id == security::id::UNDEF {
            return Err(Errno::EINVAL);
        }
        Some(id)
    } else {
        None
    };
    let cred = cx.process().cred();
    let task = crate::sched::lsm_task(cx.thread, &cred);
    let out = security::getselfattr(attr, &task, single, room)?;
    if ctx != 0 && !out.entries.is_empty() {
        cx.write_bytes(ctx, &out.entries)?;
    }
    cx.write_val(size, &out.total)?;
    if out.too_big {
        return Err(Errno::E2BIG);
    }
    if out.count == 0 {
        return Err(Errno::EOPNOTSUPP);
    }
    Ok(u64::from(out.count))
}

/// `lsm_set_self_attr(attr, ctx, size, flags)`: sets the attribute `attr` of the caller from
/// the `struct lsm_ctx` at `ctx` of `size` bytes, through the module of its ID.
pub(crate) fn lsm_set_self_attr(
    cx: &Cx<'_>,
    attr: u64,
    ctx: u64,
    size: u64,
    flags: u64,
) -> SysResult {
    let (size, flags) = (size as u32 as usize, flags as u32);
    if flags != 0 || size < LSM_CTX_HEADER {
        return Err(Errno::EINVAL);
    }
    if size > 4096 {
        return Err(Errno::E2BIG);
    }
    let buf = cx.read_bytes(ctx, size)?;
    security::setselfattr(u64::from(attr as u32), &buf, flags)?;
    Ok(0)
}

/// `lsm_list_modules(ids, size, flags)`: the IDs of the active modules in `ids`. `*size` is
/// the room of `ids`, and the call sets it to the size of all the IDs. Gives the count.
pub(crate) fn lsm_list_modules(cx: &Cx<'_>, ids: u64, size: u64, flags: u64) -> SysResult {
    if flags as u32 != 0 {
        return Err(Errno::EINVAL);
    }
    let room: u32 = cx.read_val(size)?;
    let list = security::module_ids();
    let total = (list.len() * 8) as u32;
    cx.write_val(size, &total)?;
    if room < total {
        return Err(Errno::E2BIG);
    }
    let bytes: alloc::vec::Vec<u8> = list.iter().flat_map(|id| id.to_ne_bytes()).collect();
    cx.write_bytes(ids, &bytes)?;
    Ok(list.len() as u64)
}
