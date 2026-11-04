//! The system calls of the key service: `add_key`, `request_key` and `keyctl`. The keys and
//! their rules are in `rk_proc::keys`. The handlers here copy the arguments from user memory and
//! check them in the order of Linux.

use crate::cx::{Cx, SysResult};
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_abi::native::keyctl::*;
use rk_proc::keys::{self, MAX_DESC, MAX_PAYLOAD, MAX_TYPE, Owner as _, Parent};

/// The size of a page, the limit of the callout information and of a restriction.
const PAGE_SIZE: usize = 4096;

/// Reads a key type name, as `key_get_type_from_user`.
///
/// Gives `EFAULT` for a bad address, `EINVAL` for an empty or a long name, and `EPERM` for a
/// name that starts with a dot, which is an internal type.
fn read_type(cx: &Cx<'_>, addr: u64) -> Result<Vec<u8>, Errno> {
    let kind = cx.vm()?.read_cstr(addr as usize, MAX_TYPE).map_err(|e| match e {
        Errno::ENAMETOOLONG => Errno::EINVAL,
        e => e,
    })?;
    if kind.is_empty() {
        return Err(Errno::EINVAL);
    }
    if kind[0] == b'.' {
        return Err(Errno::EPERM);
    }
    Ok(kind)
}

/// Reads a string of at most `max - 1` bytes, as `strndup_user`. A long string gives `EINVAL`.
fn read_str(cx: &Cx<'_>, addr: u64, max: usize) -> Result<Vec<u8>, Errno> {
    cx.vm()?.read_cstr(addr as usize, max).map_err(|e| match e {
        Errno::ENAMETOOLONG => Errno::EINVAL,
        e => e,
    })
}

/// Reads a payload of `len` bytes. A length of 0 gives an empty payload and reads nothing.
fn read_payload(cx: &Cx<'_>, addr: u64, len: u64) -> Result<Vec<u8>, Errno> {
    if len > MAX_PAYLOAD as u64 {
        return Err(Errno::EINVAL);
    }
    if len == 0 {
        return Ok(Vec::new());
    }
    cx.read_bytes(addr, len as usize)
}

/// Converts a key serial number to a return value.
fn serial(id: i32) -> SysResult {
    Ok(id as u32 as u64)
}

/// `add_key(type, description, payload, plen, keyring)`.
pub(crate) fn add_key(
    cx: &mut Cx<'_>,
    kind: u64,
    desc: u64,
    payload: u64,
    plen: u64,
    ring: u64,
) -> SysResult {
    if plen > MAX_PAYLOAD as u64 {
        return Err(Errno::EINVAL);
    }
    let kind = read_type(cx, kind)?;
    let desc = if desc == 0 {
        None
    } else {
        let d = read_str(cx, desc, MAX_DESC)?;
        if d.first() == Some(&b'.') && kind.starts_with(b"keyring") {
            return Err(Errno::EPERM);
        }
        (!d.is_empty()).then_some(d)
    };
    let payload = read_payload(cx, payload, plen)?;
    let id =
        cx.thread.with_keys(|k| keys::add_key(k, &kind, desc.as_deref(), payload, ring as i32))?;
    serial(id)
}

/// `request_key(type, description, callout_info, dest_keyring)`.
pub(crate) fn request_key(
    cx: &mut Cx<'_>,
    kind: u64,
    desc: u64,
    callout: u64,
    dest: u64,
) -> SysResult {
    let kind = read_type(cx, kind)?;
    let desc = read_str(cx, desc, MAX_DESC)?;
    let callout = if callout == 0 { None } else { Some(read_str(cx, callout, PAGE_SIZE)?) };
    let id = cx
        .thread
        .with_keys(|k| keys::request_key(k, &kind, &desc, callout.as_deref(), dest as i32))?;
    serial(id)
}

/// Copies `data` to the buffer of a `keyctl` operation if the buffer is not null and `data`
/// fits in `buflen` bytes. Gives the length of `data`.
fn copy_out(cx: &Cx<'_>, buf: u64, buflen: u64, data: &[u8]) -> SysResult {
    if buf != 0 && buflen >= data.len() as u64 {
        cx.write_bytes(buf, data)?;
    }
    Ok(data.len() as u64)
}

/// `keyctl(KEYCTL_SESSION_TO_PARENT)`: the parent of the caller gets its session keyring.
fn session_to_parent(cx: &Cx<'_>) -> SysResult {
    let parent = cx.process().parent();
    let threads = parent.as_ref().map(|p| p.threads()).unwrap_or_default();
    let cred = parent.as_ref().map(|p| p.cred());
    cx.thread.with_keys(|k| {
        let info = match (&parent, &cred, threads.first()) {
            (Some(p), Some(cred), Some(owner)) => Some(Parent {
                is_init: p.pid() <= 1,
                single_thread: threads.len() == 1,
                cred,
                owner: &**owner,
            }),
            _ => None,
        };
        keys::session_to_parent(k, info)
    })?;
    Ok(0)
}

/// `keyctl(KEYCTL_RESTRICT_KEYRING, keyring, type, restriction)`.
fn restrict(cx: &Cx<'_>, id: i32, kind: u64, restriction: u64) -> SysResult {
    let kind = if kind == 0 { None } else { Some(read_type(cx, kind)?) };
    let restriction = if restriction == 0 {
        None
    } else {
        if kind.is_none() {
            return Err(Errno::EINVAL);
        }
        Some(read_str(cx, restriction, PAGE_SIZE)?)
    };
    cx.thread.with_keys(|k| keys::restrict(k, id, kind.as_deref(), restriction.as_deref()))?;
    Ok(0)
}

/// Checks the error code of `KEYCTL_REJECT`. Linux takes an error number that a system call can
/// give and that does not ask for a restart.
fn check_reject_error(error: u64) -> Result<(), Errno> {
    const MAX_ERRNO: u64 = 4095;
    const ERESTARTSYS: u64 = 512;
    const ERESTART_RESTARTBLOCK: u64 = 516;
    if error == 0 || error >= MAX_ERRNO || (ERESTARTSYS..=ERESTART_RESTARTBLOCK).contains(&error) {
        return Err(Errno::EINVAL);
    }
    Ok(())
}

/// The path of the helper that constructs keys.
const REQUEST_KEY: &[u8] = b"/sbin/request-key";

/// The upcall of the key service: runs `/sbin/request-key create KEY UID GID THREAD PROCESS
/// SESSION` with the session keyring of the request and waits for its end, as
/// `call_sbin_request_key` in security/keys/request_key.c of Linux.
pub(crate) fn upcall(req: &keys::Request) -> Result<i32, Errno> {
    let mut argv = alloc::vec![REQUEST_KEY.to_vec()];
    argv.extend(req.args());
    let envp = alloc::vec![b"HOME=/".to_vec(), b"PATH=/sbin:/bin:/usr/sbin:/usr/bin".to_vec()];
    crate::umh::call(REQUEST_KEY, argv, envp, |thread| {
        thread.set_ring(keys::Slot::Session, req.session.clone(), true);
    })
}

/// `keyctl(KEYCTL_INSTANTIATE)` and `keyctl(KEYCTL_INSTANTIATE_IOV)`: the payload is in the user
/// buffers `parts`. As `keyctl_instantiate_key_common`, the payload is copied after the check of
/// the authority.
fn instantiate(cx: &Cx<'_>, id: i32, parts: &[(u64, u64)], ring: i32) -> SysResult {
    let len = parts.iter().fold(0u64, |n, p| n.saturating_add(p.1));
    if len > MAX_PAYLOAD as u64 {
        return Err(Errno::EINVAL);
    }
    let t = cx.thread;
    t.with_keys(|k| keys::check_authority(k, id))?;
    let mut payload = Vec::with_capacity(len as usize);
    for &(addr, n) in parts.iter().filter(|p| p.1 != 0) {
        payload.extend_from_slice(&cx.read_bytes(addr, n as usize)?);
    }
    t.with_keys(|k| keys::instantiate(k, id, payload, ring))?;
    Ok(0)
}

/// `keyctl(operation, arg2, arg3, arg4, arg5)`.
pub(crate) fn keyctl(cx: &mut Cx<'_>, op: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> SysResult {
    let id = a2 as i32;
    let Ok(op) = i32::try_from(op) else {
        return Err(Errno::EOPNOTSUPP);
    };
    let t = cx.thread;
    match op {
        KEYCTL_GET_KEYRING_ID => serial(t.with_keys(|k| keys::get_keyring_id(k, id, a3 != 0))?),
        KEYCTL_JOIN_SESSION_KEYRING => {
            let name = if a2 == 0 { None } else { Some(read_str(cx, a2, MAX_DESC - 1)?) };
            serial(t.with_keys(|k| keys::join_session(k, name.as_deref()))?)
        }
        KEYCTL_UPDATE => {
            let payload = read_payload(cx, a3, a4)?;
            t.with_keys(|k| keys::update(k, id, payload))?;
            Ok(0)
        }
        KEYCTL_REVOKE => t.with_keys(|k| keys::revoke(k, id)).map(|()| 0),
        KEYCTL_CHOWN => t.with_keys(|k| keys::chown(k, id, a3 as u32, a4 as u32)).map(|()| 0),
        KEYCTL_SETPERM => t.with_keys(|k| keys::set_perm(k, id, a3 as u32)).map(|()| 0),
        KEYCTL_DESCRIBE => {
            let text = t.with_keys(|k| keys::describe(k, id))?;
            copy_out(cx, a3, a4, &text)
        }
        KEYCTL_CLEAR => t.with_keys(|k| keys::clear(k, id)).map(|()| 0),
        KEYCTL_LINK => t.with_keys(|k| keys::link(k, id, a3 as i32)).map(|()| 0),
        KEYCTL_UNLINK => t.with_keys(|k| keys::unlink(k, id, a3 as i32)).map(|()| 0),
        KEYCTL_SEARCH => {
            let kind = read_type(cx, a3)?;
            let desc = read_str(cx, a4, MAX_DESC)?;
            serial(t.with_keys(|k| keys::search(k, id, &kind, &desc, a5 as i32))?)
        }
        KEYCTL_READ => {
            // A null buffer reads only the length, as a buffer of no bytes.
            let buflen = if a3 == 0 { 0 } else { a4 as usize };
            let (full, data) = t.with_keys(|k| keys::read(k, id, buflen))?;
            if a3 != 0 && !data.is_empty() {
                cx.write_bytes(a3, &data)?;
            }
            Ok(full as u64)
        }
        KEYCTL_INSTANTIATE => {
            let len = if a3 == 0 { 0 } else { a4 };
            instantiate(cx, id, &[(a3, len)], a5 as i32)
        }
        KEYCTL_INSTANTIATE_IOV => {
            let count = if a3 == 0 { 0 } else { a4 };
            let iovs = crate::fs::read_iovecs(cx, a3, count)?;
            let parts: Vec<(u64, u64)> = iovs.iter().map(|v| (v.iov_base, v.iov_len)).collect();
            instantiate(cx, id, &parts, a5 as i32)
        }
        KEYCTL_NEGATE => {
            t.with_keys(|k| keys::reject(k, id, a3 as u32, Errno::ENOKEY, a4 as i32)).map(|()| 0)
        }
        KEYCTL_REJECT => {
            check_reject_error(a4)?;
            let error = Errno::new(a4 as u16).ok_or(Errno::EINVAL)?;
            t.with_keys(|k| keys::reject(k, id, a3 as u32, error, a5 as i32)).map(|()| 0)
        }
        KEYCTL_SET_REQKEY_KEYRING => {
            let old = t.with_keys(|k| keys::set_reqkey(k, id))?;
            Ok(old as u64)
        }
        KEYCTL_SET_TIMEOUT => t.with_keys(|k| keys::set_timeout(k, id, a3 as u32)).map(|()| 0),
        KEYCTL_ASSUME_AUTHORITY => serial(t.with_keys(|k| keys::assume_authority(k, id))?),
        KEYCTL_GET_SECURITY => {
            let label = t.with_keys(|k| keys::get_security(k, id))?;
            if a3 != 0 && a4 > 0 {
                let n = label.len().min(a4 as usize);
                cx.write_bytes(a3, &label[..n])?;
            }
            Ok(label.len() as u64)
        }
        KEYCTL_SESSION_TO_PARENT => session_to_parent(cx),
        KEYCTL_INVALIDATE => t.with_keys(|k| keys::invalidate(k, id)).map(|()| 0),
        KEYCTL_RESTRICT_KEYRING => restrict(cx, id, a3, a4),
        KEYCTL_MOVE => {
            t.with_keys(|k| keys::move_key(k, id, a3 as i32, a4 as i32, a5 as u32))?;
            Ok(0)
        }
        KEYCTL_CAPABILITIES => {
            let caps = keys::capabilities();
            if a3 > 0 {
                let n = caps.len().min(a3 as usize);
                cx.write_bytes(a2, &caps[..n])?;
                // Linux clears the rest of the buffer.
                let zero = [0u8; PAGE_SIZE];
                let mut at = n as u64;
                while at < a3 {
                    let len = (a3 - at).min(PAGE_SIZE as u64) as usize;
                    cx.write_bytes(a2 + at, &zero[..len])?;
                    at += len as u64;
                }
            }
            Ok(caps.len() as u64)
        }
        _ => Err(Errno::EOPNOTSUPP),
    }
}
