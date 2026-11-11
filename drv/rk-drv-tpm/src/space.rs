//! The resource manager of `/dev/tpmrm0`, as tpm2-space.c of Linux.
//!
//! Each open file of `/dev/tpmrm0` has a space. A space keeps up to 3 transient objects and up to
//! 3 sessions. Between two commands, the objects and the sessions of a space are not in the TPM:
//! the space keeps their contexts from `TPM2_ContextSave`. Before a command, `transmit` loads them
//! again with `TPM2_ContextLoad`. After the command, it saves them again and flushes the objects.
//! Thus the files do not see the objects of the other files.
//!
//! The handle of an object in a space is a virtual handle: `0x80ffffff` for the first slot,
//! `0x80fffffe` for the second, and so on. `transmit` changes the virtual handles of a command to
//! the handles in the TPM, and changes the handle of a new object in the response to a virtual
//! handle. In the response to `TPM2_GetCapability` for the transient handles, it removes the
//! handles of the TPM that are not in the space, and changes the others to virtual handles. The
//! handles of the sessions do not change.

use crate::{ChipGuard, Result, cmd};
use alloc::vec::Vec;
use rk_abi::Errno;

/// The number of objects and the number of sessions of a space, as the size of `context_tbl`
/// and `session_tbl` of Linux.
pub const SLOTS: usize = 3;

/// The objects and sessions of an open file of `/dev/tpmrm0`, as `struct tpm_space` of Linux.
#[derive(Clone, Default)]
pub struct Space {
    /// The saved context of the object of each slot.
    objects: [Option<Vec<u8>>; SLOTS],
    /// The handle of the session of each slot, and its saved context.
    sessions: [Option<(u32, Vec<u8>)>; SLOTS],
}

/// The state of a slot of an object during a command.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Slot {
    Free,
    /// The object is in the TPM with this handle.
    Loaded(u32),
}

/// A space during a command, as `chip->work_space` of Linux: the objects and the sessions in the
/// TPM.
struct Work {
    objects: [Slot; SLOTS],
    sessions: [u32; SLOTS],
}

impl Space {
    /// Makes an empty space.
    pub fn new() -> Self {
        Self::default()
    }

    /// The handles of the sessions of the space.
    pub fn sessions(&self) -> impl Iterator<Item = u32> + '_ {
        self.sessions.iter().flatten().map(|s| s.0)
    }

    /// Tells if the space has no objects and no sessions.
    pub fn is_empty(&self) -> bool {
        self.objects.iter().all(Option::is_none) && self.sessions.iter().all(Option::is_none)
    }
}

/// The virtual handle of the slot `i`.
fn vhandle(i: usize) -> u32 {
    cmd::HT_TRANSIENT | (0x00ff_ffff - i as u32)
}

/// The slot of the virtual handle `h`, if it is a slot.
fn slot(h: u32) -> Option<usize> {
    let i = (0x00ff_ffff - (h & 0x00ff_ffff)) as usize;
    (i < SLOTS).then_some(i)
}

/// Sends `TPM2_FlushContext` for `handle`, as `tpm2_flush_context` of Linux. An error does not
/// stop the caller.
fn flush(t: &mut ChipGuard<'_>, handle: u32) {
    let _ = t.command(&cmd::flush_context(handle));
}

/// Loads the context `context`, as `tpm2_load_context` of Linux. Gives the handle in the TPM.
/// `ENOENT` tells that the TPM does not have the session now, `EINVAL` that the context is not
/// correct, and `EFAULT` another error.
fn load_context(t: &mut ChipGuard<'_>, context: &[u8]) -> Result<u32> {
    let (rc, rsp) = t.command(&cmd::context_load(context)).map_err(|_| Errno::EFAULT)?;
    match rc {
        cmd::RC_SUCCESS => cmd::be32(&rsp, cmd::HEADER_SIZE).ok_or(Errno::EFAULT),
        rc if cmd::rc_value(rc) == cmd::RC_HANDLE || rc == cmd::RC_REFERENCE_H0 => {
            Err(Errno::ENOENT)
        }
        rc if cmd::rc_value(rc) == cmd::RC_INTEGRITY => Err(Errno::EINVAL),
        _ => Err(Errno::EFAULT),
    }
}

/// Saves the context of `handle`, as `tpm2_save_context` of Linux. `ENOENT` tells that the TPM
/// does not have the handle, and `EFAULT` another error.
fn save_context(t: &mut ChipGuard<'_>, handle: u32) -> Result<Vec<u8>> {
    let (rc, rsp) = t.command(&cmd::context_save(handle)).map_err(|_| Errno::EFAULT)?;
    match rc {
        cmd::RC_SUCCESS => Ok(rsp.get(cmd::HEADER_SIZE..).ok_or(Errno::EFAULT)?.to_vec()),
        rc if cmd::rc_value(rc) == cmd::RC_REFERENCE_H0 => Err(Errno::ENOENT),
        _ => Err(Errno::EFAULT),
    }
}

/// Flushes the objects and the sessions of `work` from the TPM after an error, as
/// `tpm2_flush_space` of Linux.
fn flush_work(t: &mut ChipGuard<'_>, work: &Work) {
    for s in work.objects {
        if let Slot::Loaded(h) = s {
            flush(t, h);
        }
    }
    for &h in work.sessions.iter().filter(|&&h| h != 0) {
        flush(t, h);
    }
}

/// Loads the objects and the sessions of `space` into the TPM, as `tpm2_load_space` of Linux. A
/// session that the TPM does not have now goes from the space. On an error, the caller flushes
/// `work`.
fn load_space(t: &mut ChipGuard<'_>, space: &Space, work: &mut Work) -> Result<()> {
    for (i, context) in space.objects.iter().enumerate() {
        if let Some(context) = context {
            work.objects[i] = Slot::Loaded(load_context(t, context)?);
        }
    }
    for (i, session) in space.sessions.iter().enumerate() {
        let Some((handle, context)) = session else { continue };
        work.sessions[i] = *handle;
        match load_context(t, context) {
            Err(Errno::ENOENT) => work.sessions[i] = 0,
            Err(e) => return Err(e),
            Ok(h) if h != *handle => return Err(Errno::EFAULT),
            Ok(_) => {}
        }
    }
    Ok(())
}

/// Changes the virtual handles in the handle area of the command `c` to the handles in the TPM,
/// as `tpm2_map_command` of Linux. `nr` is the number of handles of the command.
fn map_command(work: &Work, c: &mut [u8], nr: usize) -> Result<()> {
    for k in 0..nr {
        let at = cmd::HEADER_SIZE + 4 * k;
        let h = cmd::be32(c, at).ok_or(Errno::EINVAL)?;
        if h & 0xff00_0000 != cmd::HT_TRANSIENT {
            continue;
        }
        let Some(Slot::Loaded(p)) = slot(h).map(|i| work.objects[i]) else {
            return Err(Errno::EINVAL);
        };
        c[at..at + 4].copy_from_slice(&p.to_be_bytes());
    }
    Ok(())
}

/// The slot of the object with the handle `p` in the TPM, or a new slot for it with `alloc`, as
/// `tpm2_map_to_vhandle` of Linux. Gives the virtual handle.
fn map_to_vhandle(work: &mut Work, p: u32, alloc: bool) -> Option<u32> {
    let i = if alloc {
        let i = work.objects.iter().position(|s| *s == Slot::Free)?;
        work.objects[i] = Slot::Loaded(p);
        i
    } else {
        work.objects.iter().position(|s| *s == Slot::Loaded(p))?
    };
    Some(vhandle(i))
}

/// Changes the handle of a new object in the response `r` to a virtual handle, and adds a new
/// session to the space, as `tpm2_map_response_header` of Linux. With no free slot, it flushes
/// the new object or session and gives `ENOMEM`.
fn map_response_header(
    t: &mut ChipGuard<'_>,
    work: &mut Work,
    attrs: u32,
    r: &mut [u8],
) -> Result<()> {
    if cmd::code(r) != Some(cmd::RC_SUCCESS) || attrs & (1 << cmd::CC_ATTR_RHANDLE) == 0 {
        return Ok(());
    }
    let p = cmd::be32(r, cmd::HEADER_SIZE).ok_or(Errno::EFAULT)?;
    let at = cmd::HEADER_SIZE;
    let added = match p & 0xff00_0000 {
        cmd::HT_TRANSIENT => map_to_vhandle(work, p, true).map(|v| {
            r[at..at + 4].copy_from_slice(&v.to_be_bytes());
        }),
        cmd::HT_HMAC_SESSION | cmd::HT_POLICY_SESSION => {
            work.sessions.iter().position(|&s| s == 0).map(|i| work.sessions[i] = p)
        }
        _ => Some(()),
    };
    if added.is_none() {
        flush(t, p);
        return Err(Errno::ENOMEM);
    }
    Ok(())
}

/// Removes the transient handles that are not in the space from a response to
/// `TPM2_GetCapability(TPM_CAP_HANDLES)`, and changes the others to virtual handles, as
/// `tpm2_map_response_body` of Linux. Gives the new length of the response.
fn map_response_body(work: &mut Work, cc: u32, r: &mut [u8]) -> Result<usize> {
    let len = r.len();
    if cc != cmd::CC_GET_CAPABILITY || cmd::code(r) != Some(cmd::RC_SUCCESS) {
        return Ok(len);
    }
    if len < cmd::HEADER_SIZE + 9 {
        return Err(Errno::EFAULT);
    }
    if cmd::be32(r, cmd::HEADER_SIZE + 1) != Some(cmd::CAP_HANDLES) {
        return Ok(len);
    }
    let count = cmd::be32(r, cmd::HEADER_SIZE + 5).ok_or(Errno::EFAULT)? as usize;
    let start = cmd::HEADER_SIZE + 9;
    if count.checked_mul(4).and_then(|n| n.checked_add(start)) != Some(len) {
        return Err(Errno::EFAULT);
    }
    let mut j = 0;
    for i in 0..count {
        let p = cmd::be32(r, start + 4 * i).ok_or(Errno::EFAULT)?;
        let h = if p & 0xff00_0000 == cmd::HT_TRANSIENT {
            match map_to_vhandle(work, p, false) {
                Some(v) => v,
                None => continue,
            }
        } else {
            p
        };
        r[start + 4 * j..start + 4 * j + 4].copy_from_slice(&h.to_be_bytes());
        j += 1;
    }
    let len = start + 4 * j;
    r[2..6].copy_from_slice(&(len as u32).to_be_bytes());
    r[cmd::HEADER_SIZE + 5..cmd::HEADER_SIZE + 9].copy_from_slice(&(j as u32).to_be_bytes());
    Ok(len)
}

/// Saves the objects and the sessions of `work` and flushes the objects from the TPM, as
/// `tpm2_save_space` of Linux. An object or a session that the TPM does not have now goes from
/// the space. Gives the new space.
fn save_space(t: &mut ChipGuard<'_>, work: &mut Work) -> Result<Space> {
    let mut space = Space::new();
    for i in 0..SLOTS {
        let Slot::Loaded(h) = work.objects[i] else { continue };
        match save_context(t, h) {
            Err(Errno::ENOENT) => work.objects[i] = Slot::Free,
            Err(e) => return Err(e),
            Ok(context) => {
                flush(t, h);
                work.objects[i] = Slot::Free;
                space.objects[i] = Some(context);
            }
        }
    }
    for i in 0..SLOTS {
        let h = work.sessions[i];
        if h == 0 {
            continue;
        }
        match save_context(t, h) {
            Err(Errno::ENOENT) => work.sessions[i] = 0,
            Err(e) => return Err(e),
            Ok(context) => space.sessions[i] = Some((h, context)),
        }
    }
    // A saved session is not loaded, and the TPM keeps it for a later `TPM2_ContextLoad`.
    work.sessions = [0; SLOTS];
    Ok(space)
}

/// The response of the resource manager to a command that the TPM does not have, as
/// `tpm_dev_transmit` of Linux makes it: `TPM_RC_COMMAND_CODE` in the layer of the resource
/// manager.
fn bad_command() -> Vec<u8> {
    let mut r = Vec::with_capacity(cmd::HEADER_SIZE);
    r.extend_from_slice(&cmd::ST_NO_SESSIONS.to_be_bytes());
    r.extend_from_slice(&(cmd::HEADER_SIZE as u32).to_be_bytes());
    r.extend_from_slice(&(cmd::RC_COMMAND_CODE | cmd::RC_RESMGR_LAYER).to_be_bytes());
    r
}

/// Sends the command `c` in the space `space`, as `tpm2_prepare_space`, `tpm_transmit` and
/// `tpm2_commit_space` of Linux. The caller has the chip for all of the commands. Gives the
/// response. On an error, the space does not change, and the TPM does not keep the objects and
/// sessions of the space that were loaded.
///
/// # Errors
///
/// `EINVAL` for a command that is too short, for a command when the chip has no attributes of
/// the commands, and for a virtual handle that is not in the space. `ENOMEM` when the space has
/// no free slot for a new object or session. `EFAULT` and the other errors of
/// `ChipGuard::transmit` for an error of the TPM.
pub fn transmit(t: &mut ChipGuard<'_>, space: &mut Space, c: &[u8]) -> Result<Vec<u8>> {
    if c.len() < cmd::HEADER_SIZE || !t.chip().has_cc_attrs() {
        return Err(Errno::EINVAL);
    }
    let cc = cmd::code(c).ok_or(Errno::EINVAL)?;
    let Some(attrs) = t.chip().cc_attrs(cc) else {
        return Ok(bad_command());
    };
    let nr = ((attrs >> cmd::CC_ATTR_CHANDLES) & 7) as usize;
    if c.len() < cmd::HEADER_SIZE + 4 * nr {
        return Err(Errno::EINVAL);
    }
    let mut work = Work { objects: [Slot::Free; SLOTS], sessions: [0; SLOTS] };
    let mut c = c.to_vec();
    let done = load_space(t, space, &mut work)
        .and_then(|()| map_command(&work, &mut c, nr))
        .and_then(|()| t.command(&c))
        .and_then(|(_, mut r)| {
            map_response_header(t, &mut work, attrs, &mut r)?;
            let len = map_response_body(&mut work, cc, &mut r)?;
            r.truncate(len);
            let new = save_space(t, &mut work)?;
            Ok((r, new))
        });
    match done {
        Ok((r, new)) => {
            *space = new;
            Ok(r)
        }
        Err(e) => {
            flush_work(t, &work);
            Err(e)
        }
    }
}

/// Flushes the sessions of a space whose file closes, as `tpm2_del_space` of Linux. The TPM
/// does not keep the saved objects, so they only go from memory.
pub fn release(t: &mut ChipGuard<'_>, space: &mut Space) {
    for h in space.sessions().collect::<Vec<u32>>() {
        flush(t, h);
    }
    *space = Space::new();
}
