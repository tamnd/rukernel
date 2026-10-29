//! The message queues of System V: `msgget`, `msgsnd`, `msgrcv` and `msgctl`, from ipc/msg.c.
//!
//! A queue holds messages in the order of `msgsnd`. Each message has a type, and `msgrcv` selects
//! a message by its type. The queue holds at most `msg_qbytes` bytes, and at most `msg_qnum`
//! messages. A send to a full queue and a receive that finds no message wait, unless the call has
//! `IPC_NOWAIT`. A signal stops the wait, and the removal of the queue gives `EIDRM`.
//!
//! The pure part of the queue is `rk_vfs::ipc::MsgQueue`. The limits `msgmax`, `msgmnb` and
//! `msgmni` are in `rk_vfs::ipc`, so procfs can change them.
//!
//! The calls check the permissions of a queue as `ipcperms` of Linux, and only the owner, the
//! creator or a process with `CAP_SYS_ADMIN` can change or remove a queue.

use crate::cx::{Cx, SysResult};
use crate::ns::PerNs;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_vfs::WaitQueue;
use rk_vfs::cred::{IpcOwner, cap};
use rk_vfs::ipc::{MSG_NEXT_ID, MSGMAX, MSGMNB, MSGMNI, Msg, MsgQueue, Search};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// The key that always makes a new queue.
const IPC_PRIVATE: i32 = 0;
/// The flags of `msgget`.
const IPC_CREAT: u32 = 0o1000;
const IPC_EXCL: u32 = 0o2000;
/// The flags of `msgsnd` and `msgrcv`.
const IPC_NOWAIT: u32 = 0o4000;
const MSG_NOERROR: u32 = 0o10000;
const MSG_EXCEPT: u32 = 0o20000;
const MSG_COPY: u32 = 0o40000;
/// The commands of `msgctl`.
const IPC_RMID: u32 = 0;
const IPC_SET: u32 = 1;
const IPC_STAT: u32 = 2;
const IPC_INFO: u32 = 3;
const MSG_STAT: u32 = 11;
const MSG_INFO: u32 = 12;
const MSG_STAT_ANY: u32 = 13;
/// The bit of the command that asks for the 64-bit structures. They are the only structures.
const IPC_64: u32 = 0x100;

/// The fixed values of `struct msginfo`, as the defaults of Linux.
const MSGSSZ: i32 = 16;
const MSGSEG: u16 = 0xffff;
const MSGMNB_DEFAULT: i32 = 16384;
const MSGPOOL: i32 = 32000 * MSGMNB_DEFAULT / 1024;

/// The permissions of an IPC object, as `struct ipc64_perm` of x86-64.
#[derive(Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
struct IpcPerm {
    key: i32,
    uid: u32,
    gid: u32,
    cuid: u32,
    cgid: u32,
    mode: u16,
    pad1: u16,
    seq: u16,
    pad2: u16,
    pad3: u32,
    unused: [u64; 2],
}

impl IpcPerm {
    /// The owner, the creator and the mode, for the permission checks.
    fn owner(&self) -> IpcOwner {
        IpcOwner {
            uid: self.uid,
            gid: self.gid,
            cuid: self.cuid,
            cgid: self.cgid,
            mode: u32::from(self.mode),
        }
    }
}

/// The state of a queue, as `struct msqid64_ds` of x86-64.
#[derive(Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
struct MsqidDs {
    perm: IpcPerm,
    stime: i64,
    rtime: i64,
    ctime: i64,
    cbytes: u64,
    qnum: u64,
    qbytes: u64,
    lspid: i32,
    lrpid: i32,
    unused: [u64; 2],
}

/// The limits and the use, as `struct msginfo`.
#[derive(Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
struct MsgInfo {
    msgpool: i32,
    msgmap: i32,
    msgmax: i32,
    msgmnb: i32,
    msgmni: i32,
    msgssz: i32,
    msgtql: i32,
    msgseg: u16,
    pad: u16,
}

/// A queue in the table.
struct Queue {
    perm: IpcPerm,
    msgs: MsgQueue,
    stime: i64,
    rtime: i64,
    ctime: i64,
    lspid: i32,
    lrpid: i32,
}

impl Queue {
    fn ds(&self) -> MsqidDs {
        MsqidDs {
            perm: self.perm,
            stime: self.stime,
            rtime: self.rtime,
            ctime: self.ctime,
            cbytes: self.msgs.cbytes() as u64,
            qnum: self.msgs.qnum() as u64,
            qbytes: self.msgs.qbytes() as u64,
            lspid: self.lspid,
            lrpid: self.lrpid,
            unused: [0; 2],
        }
    }
}

/// The queues by ID, and the next ID.
struct Table {
    queues: BTreeMap<i32, Queue>,
    next: i32,
}

impl Table {
    fn get(&mut self, id: i32) -> Result<&mut Queue, Errno> {
        self.queues.get_mut(&id).ok_or(Errno::EINVAL)
    }
}

/// An empty table.
const fn empty() -> Table {
    Table { queues: BTreeMap::new(), next: 0 }
}

/// The table of each IPC namespace.
static TABLE: PerNs<Table> = PerNs::new(empty(), empty);

/// Removes the objects of the IPC namespace `id` that stops, as `msg_exit_ns` of Linux.
pub(crate) fn exit_ns(id: u32) {
    TABLE.exit(id);
}

/// The tasks that wait in `msgsnd` and `msgrcv`. Each change of a queue wakes them, and each one
/// tests its queue again.
static WAIT: WaitQueue = WaitQueue::new();

fn now() -> i64 {
    crate::info::realtime().sec
}

fn pid(cx: &Cx<'_>) -> i32 {
    cx.process().pid() as i32
}

pub(crate) fn msgget(cx: &Cx<'_>, key: u64, flags: u64) -> SysResult {
    let key = key as i32;
    let flags = flags as u32;
    let c = cx.process().cred();
    let mut table = TABLE.get().lock();
    if key != IPC_PRIVATE {
        let found = table
            .queues
            .iter()
            .find(|(_, q)| q.perm.key == key)
            .map(|(id, q)| (*id, q.perm.owner()));
        if let Some((id, owner)) = found {
            if flags & (IPC_CREAT | IPC_EXCL) == IPC_CREAT | IPC_EXCL {
                return Err(Errno::EEXIST);
            }
            c.ipc_permission(&owner, flags & 0o777)?;
            return Ok(id as u64);
        }
        if flags & IPC_CREAT == 0 {
            return Err(Errno::ENOENT);
        }
    }
    if table.queues.len() >= MSGMNI.get() as usize {
        return Err(Errno::ENOSPC);
    }
    let id = rk_vfs::ipc::alloc_id(&MSG_NEXT_ID, table.next, |id| table.queues.contains_key(&id));
    table.next = id.wrapping_add(1) & i32::MAX;
    // The owner and the creator are the effective IDs of the caller, as `ipc_addid` of Linux.
    let perm = IpcPerm {
        key,
        uid: c.euid,
        gid: c.egid,
        cuid: c.euid,
        cgid: c.egid,
        mode: (flags & 0o777) as u16,
        ..IpcPerm::default()
    };
    let qbytes = MSGMNB.get().max(0) as usize;
    let queue = Queue {
        perm,
        msgs: MsgQueue::new(qbytes),
        stime: 0,
        rtime: 0,
        ctime: now(),
        lspid: 0,
        lrpid: 0,
    };
    table.queues.insert(id, queue);
    Ok(id as u64)
}

pub(crate) fn msgsnd(cx: &Cx<'_>, id: u64, msgp: u64, msgsz: u64, flags: u64) -> SysResult {
    let id = id as i32;
    let flags = flags as u32;
    let size = msgsz as i64;
    if size > i64::from(MSGMAX.get()) || size < 0 || id < 0 {
        return Err(Errno::EINVAL);
    }
    let mtype: i64 = cx.read_val(msgp)?;
    if mtype < 1 {
        return Err(Errno::EINVAL);
    }
    let text = cx.read_bytes(msgp.wrapping_add(8), size as usize)?;
    let c = cx.process().cred();
    let pid = pid(cx);
    let thread = cx.thread;
    let mut msg = Some(Msg { mtype, text });
    let mut step = || {
        let mut table = TABLE.get().lock();
        let Some(q) = table.queues.get_mut(&id) else { return Some(Err(Errno::EIDRM)) };
        if let Err(e) = c.ipc_permission(&q.perm.owner(), 0o222) {
            return Some(Err(e));
        }
        let len = msg.as_ref().map_or(0, |m| m.text.len());
        if q.msgs.fits(len) {
            if let Some(m) = msg.take() {
                q.msgs.push(m);
            }
            q.lspid = pid;
            q.stime = now();
            return Some(Ok(()));
        }
        if flags & IPC_NOWAIT != 0 {
            return Some(Err(Errno::EAGAIN));
        }
        if thread.signal_pending() {
            return Some(Err(Errno::ERESTARTNOHAND));
        }
        None
    };
    // The first try finds a queue that is not there with `EINVAL`, and a later one with `EIDRM`.
    if !TABLE.get().lock().queues.contains_key(&id) {
        return Err(Errno::EINVAL);
    }
    let r = match step() {
        Some(r) => r,
        None => WAIT.wait_until(&mut step),
    };
    if r.is_ok() {
        WAIT.wake_all();
    }
    r.map(|()| 0)
}

pub(crate) fn msgrcv(
    cx: &Cx<'_>,
    id: u64,
    msgp: u64,
    msgsz: u64,
    msgtyp: u64,
    flags: u64,
) -> SysResult {
    let id = id as i32;
    let flags = flags as u32;
    let bufsz = msgsz as i64;
    if id < 0 || bufsz < 0 {
        return Err(Errno::EINVAL);
    }
    let copy = flags & MSG_COPY != 0;
    if copy && (flags & MSG_EXCEPT != 0 || flags & IPC_NOWAIT == 0) {
        return Err(Errno::EINVAL);
    }
    let search = Search::new(msgtyp as i64, flags & MSG_EXCEPT != 0, copy);
    let bufsz = bufsz as usize;
    let c = cx.process().cred();
    let pid = pid(cx);
    let thread = cx.thread;
    let mut step = || {
        let mut table = TABLE.get().lock();
        let Some(q) = table.queues.get_mut(&id) else { return Some(Err(Errno::EIDRM)) };
        if let Err(e) = c.ipc_permission(&q.perm.owner(), 0o444) {
            return Some(Err(e));
        }
        if let Some(i) = q.msgs.find(search) {
            let len = q.msgs.get(i).map_or(0, |m| m.text.len());
            if bufsz < len && flags & MSG_NOERROR == 0 {
                return Some(Err(Errno::E2BIG));
            }
            if copy {
                // The copy has room for at most `msgmax` bytes, as `copy_msg` of Linux.
                if bufsz.min(MSGMAX.get().max(0) as usize) < len {
                    return Some(Err(Errno::EINVAL));
                }
                return q.msgs.get(i).cloned().map(Ok);
            }
            let msg = q.msgs.remove(i);
            q.lrpid = pid;
            q.rtime = now();
            return msg.map(Ok);
        }
        if flags & IPC_NOWAIT != 0 {
            return Some(Err(Errno::ENOMSG));
        }
        if thread.signal_pending() {
            return Some(Err(Errno::ERESTARTNOHAND));
        }
        None
    };
    if !TABLE.get().lock().queues.contains_key(&id) {
        return Err(Errno::EINVAL);
    }
    let msg = match step() {
        Some(r) => r,
        None => WAIT.wait_until(&mut step),
    }?;
    if !copy {
        WAIT.wake_all();
    }
    let len = msg.text.len().min(bufsz);
    cx.write_val(msgp, &msg.mtype)?;
    cx.write_bytes(msgp.wrapping_add(8), &msg.text[..len])?;
    Ok(len as u64)
}

pub(crate) fn msgctl(cx: &Cx<'_>, id: u64, cmd: u64, buf: u64) -> SysResult {
    let id = id as i32;
    let cmd = cmd as i32;
    if id < 0 || cmd < 0 {
        return Err(Errno::EINVAL);
    }
    let cmd = cmd as u32 & !IPC_64;
    let c = cx.process().cred();
    // `IPC_SET` reads the new values before it finds the queue, as Linux.
    let new: Option<MsqidDs> = if cmd == IPC_SET { Some(cx.read_val(buf)?) } else { None };
    let mut table = TABLE.get().lock();
    match cmd {
        IPC_INFO | MSG_INFO => {
            let mut info = MsgInfo {
                msgpool: MSGPOOL,
                msgmap: MSGMNB_DEFAULT,
                msgmax: MSGMAX.get(),
                msgmnb: MSGMNB.get(),
                msgmni: MSGMNI.get(),
                msgssz: MSGSSZ,
                msgtql: MSGMNB_DEFAULT,
                msgseg: MSGSEG,
                pad: 0,
            };
            if cmd == MSG_INFO {
                info.msgpool = table.queues.len() as i32;
                info.msgmap = table.queues.values().map(|q| q.msgs.qnum() as i32).sum();
                info.msgtql = table.queues.values().map(|q| q.msgs.cbytes() as i32).sum();
            }
            let max = table.queues.keys().next_back().copied().unwrap_or(0);
            drop(table);
            cx.write_val(buf, &info)?;
            Ok(max as u64)
        }
        IPC_STAT | MSG_STAT | MSG_STAT_ANY => {
            let q = table.get(id)?;
            if cmd != MSG_STAT_ANY {
                c.ipc_permission(&q.perm.owner(), 0o444)?;
            }
            let ds = q.ds();
            drop(table);
            cx.write_val(buf, &ds)?;
            Ok(if cmd == IPC_STAT { 0 } else { id as u64 })
        }
        IPC_SET => {
            let ds = new.ok_or(Errno::EINVAL)?;
            let q = table.get(id)?;
            if !c.ipc_owns(&q.perm.owner()) {
                return Err(Errno::EPERM);
            }
            // A limit above `msgmnb` needs `CAP_SYS_RESOURCE`, as `msgctl_down` of Linux.
            if ds.qbytes > MSGMNB.get().max(0) as u64 && !c.capable(cap::SYS_RESOURCE) {
                return Err(Errno::EPERM);
            }
            // -1 is not a valid ID, as `ipc_update_perm` of Linux.
            if ds.perm.uid == u32::MAX || ds.perm.gid == u32::MAX {
                return Err(Errno::EINVAL);
            }
            q.perm.uid = ds.perm.uid;
            q.perm.gid = ds.perm.gid;
            q.perm.mode = (q.perm.mode & !0o777) | (ds.perm.mode & 0o777);
            q.msgs.set_qbytes(usize::try_from(ds.qbytes).unwrap_or(usize::MAX));
            q.ctime = now();
            drop(table);
            // A sender can fit now, and a waiter can lose its permission.
            WAIT.wake_all();
            Ok(0)
        }
        IPC_RMID => {
            if !c.ipc_owns(&table.get(id)?.perm.owner()) {
                return Err(Errno::EPERM);
            }
            table.queues.remove(&id);
            drop(table);
            // The waiters see that the queue is gone and give `EIDRM`.
            WAIT.wake_all();
            Ok(0)
        }
        _ => Err(Errno::EINVAL),
    }
}

/// The text of `/proc/sysvipc/msg`, as `sysvipc_msg_proc_show` of Linux.
pub(crate) fn proc_text() -> Vec<u8> {
    let mut out = String::from(
        "       key      msqid perms      cbytes       qnum lspid lrpid   uid   gid  cuid  cgid      \
         stime      rtime      ctime\n",
    );
    for (id, q) in &TABLE.get().lock().queues {
        let p = &q.perm;
        out.push_str(&format!(
            "{:10} {:10}  {:4o}  {:10} {:10} {:5} {:5} {:5} {:5} {:5} {:5} {:10} {:10} {:10}\n",
            p.key,
            id,
            p.mode,
            q.msgs.cbytes(),
            q.msgs.qnum(),
            q.lspid,
            q.lrpid,
            p.uid,
            p.gid,
            p.cuid,
            p.cgid,
            q.stime,
            q.rtime,
            q.ctime,
        ));
    }
    out.into_bytes()
}

/// The text of the file `name` of `/proc/sysvipc`.
pub(crate) fn sysvipc(name: &str) -> Vec<u8> {
    match name {
        "msg" => proc_text(),
        "sem" => crate::sem::proc_text(),
        "shm" => crate::shm::proc_text(),
        _ => Vec::new(),
    }
}
