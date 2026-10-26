//! The semaphores of System V: `semget`, `semop`, `semtimedop` and `semctl`, from ipc/sem.c.
//!
//! A set holds one or more semaphores. `semop` does all its operations or none of them: if one
//! operation cannot go on, the call waits until a change of the set lets all of them go on. A
//! signal stops the wait with `EINTR`, and the end of the timeout of `semtimedop` gives `EAGAIN`.
//!
//! An operation with `SEM_UNDO` records the opposite change for the process. When the process
//! ends, the kernel does the recorded changes, as `exit_sem` of Linux.
//!
//! The calls do not check the permissions, as the calls of the shared memory.

use crate::cx::{Cx, SysResult};
use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_frame::sync::SpinLock;
use rk_vfs::WaitQueue;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// The key that always makes a new set.
const IPC_PRIVATE: i32 = 0;
/// The flags of `semget`.
const IPC_CREAT: u32 = 0o1000;
const IPC_EXCL: u32 = 0o2000;
/// The flags of an operation.
const IPC_NOWAIT: i16 = 0o4000;
const SEM_UNDO: i16 = 0x1000;
/// The commands of `semctl`.
const IPC_RMID: u32 = 0;
const IPC_SET: u32 = 1;
const IPC_STAT: u32 = 2;
const IPC_INFO: u32 = 3;
const GETPID: u32 = 11;
const GETVAL: u32 = 12;
const GETALL: u32 = 13;
const GETNCNT: u32 = 14;
const GETZCNT: u32 = 15;
const SETVAL: u32 = 16;
const SETALL: u32 = 17;
const SEM_STAT: u32 = 18;
const SEM_INFO: u32 = 19;
const SEM_STAT_ANY: u32 = 20;
/// The bit of the command that asks for the 64-bit structures. They are the only structures.
const IPC_64: u32 = 0x100;

/// The limits, as the defaults of Linux.
const SEMMSL: i32 = 32000;
const SEMMNI: usize = 32000;
const SEMMNS: i32 = SEMMNI as i32 * SEMMSL;
const SEMOPM: usize = 500;
const SEMVMX: i32 = 32767;
const SEMAEM: i32 = SEMVMX;

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

/// The state of a set, as `struct semid64_ds` of x86-64.
#[derive(Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
struct SemidDs {
    perm: IpcPerm,
    otime: i64,
    unused1: u64,
    ctime: i64,
    unused2: u64,
    nsems: u64,
    unused3: u64,
    unused4: u64,
}

/// The limits and the use, as `struct seminfo`.
#[derive(Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
struct SemInfo {
    semmap: i32,
    semmni: i32,
    semmns: i32,
    semmnu: i32,
    semmsl: i32,
    semopm: i32,
    semume: i32,
    semusz: i32,
    semvmx: i32,
    semaem: i32,
}

/// One operation of `semop`, as `struct sembuf`.
#[derive(Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
struct SemBuf {
    num: u16,
    op: i16,
    flg: i16,
}

/// One semaphore.
#[derive(Clone, Copy, Default)]
struct Sem {
    val: i32,
    /// The process of the last operation.
    pid: i32,
    /// The tasks that wait for the value to go up, and for the value to be 0.
    ncnt: u32,
    zcnt: u32,
}

/// A set in the table.
struct Set {
    perm: IpcPerm,
    members: Vec<Sem>,
    otime: i64,
    ctime: i64,
}

impl Set {
    fn ds(&self) -> SemidDs {
        SemidDs {
            perm: self.perm,
            otime: self.otime,
            ctime: self.ctime,
            nsems: self.members.len() as u64,
            ..SemidDs::default()
        }
    }
}

/// The sets by ID, the next ID, and the changes that `SEM_UNDO` recorded by process and set.
struct Table {
    sets: BTreeMap<i32, Set>,
    next: i32,
    undo: BTreeMap<(i32, i32), Vec<i32>>,
}

impl Table {
    fn get(&mut self, id: i32) -> Result<&mut Set, Errno> {
        self.sets.get_mut(&id).ok_or(Errno::EINVAL)
    }

    /// Drops the recorded changes of the semaphore `num` of the set `id`, or of each semaphore
    /// for `None`, as a `SETVAL` and a `SETALL` of Linux do.
    fn clear_undo(&mut self, id: i32, num: Option<usize>) {
        for ((_, set), adj) in &mut self.undo {
            if *set == id {
                match num {
                    Some(n) => adj[n] = 0,
                    None => adj.fill(0),
                }
            }
        }
    }
}

static TABLE: SpinLock<Table> =
    SpinLock::new(Table { sets: BTreeMap::new(), next: 0, undo: BTreeMap::new() });

/// The tasks that wait in `semop`. Each change of a set wakes them, and each one tests its
/// operations again.
static WAIT: WaitQueue = WaitQueue::new();

fn now() -> i64 {
    crate::info::realtime().sec
}

fn pid(cx: &Cx<'_>) -> i32 {
    cx.process().pid() as i32
}

pub(crate) fn semget(_cx: &Cx<'_>, key: u64, nsems: u64, flags: u64) -> SysResult {
    let key = key as i32;
    let nsems = nsems as i32;
    let flags = flags as u32;
    if !(0..=SEMMSL).contains(&nsems) {
        return Err(Errno::EINVAL);
    }
    let mut table = TABLE.lock();
    if key != IPC_PRIVATE {
        let found = table
            .sets
            .iter()
            .find(|(_, s)| s.perm.key == key)
            .map(|(id, s)| (*id, s.members.len()));
        if let Some((id, len)) = found {
            if flags & (IPC_CREAT | IPC_EXCL) == IPC_CREAT | IPC_EXCL {
                return Err(Errno::EEXIST);
            }
            if nsems as usize > len {
                return Err(Errno::EINVAL);
            }
            return Ok(id as u64);
        }
        if flags & IPC_CREAT == 0 {
            return Err(Errno::ENOENT);
        }
    }
    if nsems == 0 {
        return Err(Errno::EINVAL);
    }
    let used: usize = table.sets.values().map(|s| s.members.len()).sum();
    if table.sets.len() >= SEMMNI || used + nsems as usize > SEMMNS as usize {
        return Err(Errno::ENOSPC);
    }
    let id = table.next;
    table.next = table.next.wrapping_add(1) & i32::MAX;
    let perm = IpcPerm { key, mode: (flags & 0o777) as u16, ..IpcPerm::default() };
    let set = Set { perm, members: vec![Sem::default(); nsems as usize], otime: 0, ctime: now() };
    table.sets.insert(id, set);
    Ok(id as u64)
}

/// The result of one try of the operations of `semop`.
enum Try {
    Done,
    /// The operation at the index cannot go on. The flag tells if it waits for 0.
    Blocked(usize, bool),
}

/// Does all the operations `sops` on the set `id`, or none of them, as `perform_atomic_semop`
/// of Linux.
fn try_ops(table: &mut Table, id: i32, sops: &[SemBuf], pid: i32) -> Result<Try, Errno> {
    let set = table.sets.get_mut(&id).ok_or(Errno::EIDRM)?;
    let mut vals: Vec<i32> = set.members.iter().map(|s| s.val).collect();
    for (i, sop) in sops.iter().enumerate() {
        let val = &mut vals[usize::from(sop.num)];
        let op = i32::from(sop.op);
        if op == 0 {
            if *val != 0 {
                return Ok(Try::Blocked(i, true));
            }
            continue;
        }
        let new = *val + op;
        if new < 0 {
            return Ok(Try::Blocked(i, false));
        }
        if new > SEMVMX {
            return Err(Errno::ERANGE);
        }
        *val = new;
    }
    // The changes that `SEM_UNDO` records must stay in the range of Linux.
    let nsems = set.members.len();
    let mut adj = table.undo.get(&(pid, id)).cloned().unwrap_or_else(|| vec![0; nsems]);
    let mut undo = false;
    for sop in sops.iter().filter(|s| s.flg & SEM_UNDO != 0 && s.op != 0) {
        let a = &mut adj[usize::from(sop.num)];
        *a -= i32::from(sop.op);
        if !(-SEMAEM - 1..=SEMAEM).contains(a) {
            return Err(Errno::ERANGE);
        }
        undo = true;
    }
    let set = table.sets.get_mut(&id).ok_or(Errno::EIDRM)?;
    for (sem, val) in set.members.iter_mut().zip(vals) {
        sem.val = val;
    }
    for sop in sops {
        set.members[usize::from(sop.num)].pid = pid;
    }
    set.otime = now();
    if undo {
        table.undo.insert((pid, id), adj);
    }
    Ok(Try::Done)
}

/// Counts the task as a waiter of the semaphore `num`, or takes the count away.
fn count_waiter(table: &mut Table, id: i32, num: usize, zero: bool, add: bool) {
    let Some(sem) = table.sets.get_mut(&id).and_then(|s| s.members.get_mut(num)) else { return };
    let count = if zero { &mut sem.zcnt } else { &mut sem.ncnt };
    *count = if add { *count + 1 } else { count.saturating_sub(1) };
}

pub(crate) fn semop(cx: &Cx<'_>, id: u64, sops: u64, nsops: u64) -> SysResult {
    do_semop(cx, id, sops, nsops, None)
}

pub(crate) fn semtimedop(cx: &Cx<'_>, id: u64, sops: u64, nsops: u64, timeout: u64) -> SysResult {
    let deadline = crate::poll::timespec_deadline(cx, timeout)?;
    do_semop(cx, id, sops, nsops, deadline)
}

fn do_semop(cx: &Cx<'_>, id: u64, sops: u64, nsops: u64, deadline: Option<u64>) -> SysResult {
    let id = id as i32;
    let n = nsops as usize;
    if n < 1 || id < 0 {
        return Err(Errno::EINVAL);
    }
    if n > SEMOPM {
        return Err(Errno::E2BIG);
    }
    let size = core::mem::size_of::<SemBuf>();
    let bytes = cx.read_bytes(sops, n * size)?;
    let ops: Vec<SemBuf> =
        bytes.chunks_exact(size).filter_map(|c| SemBuf::read_from_bytes(c).ok()).collect();
    let pid = pid(cx);
    {
        let mut table = TABLE.lock();
        let set = table.get(id)?;
        if ops.iter().any(|s| usize::from(s.num) >= set.members.len()) {
            return Err(Errno::EFBIG);
        }
    }
    let thread = cx.thread;
    // The semaphore that the task waits for, so the end of the wait takes the count away.
    let mut waits: Option<(usize, bool)> = None;
    let mut step = || {
        let mut table = TABLE.lock();
        let r = match try_ops(&mut table, id, &ops, pid) {
            Ok(Try::Done) => Some(Ok(())),
            Err(e) => Some(Err(e)),
            Ok(Try::Blocked(i, _)) if ops[i].flg & IPC_NOWAIT != 0 => Some(Err(Errno::EAGAIN)),
            Ok(Try::Blocked(..)) if thread.signal_pending() => Some(Err(Errno::EINTR)),
            Ok(Try::Blocked(i, zero)) => {
                let num = usize::from(ops[i].num);
                if waits != Some((num, zero)) {
                    if let Some((n, z)) = waits.take() {
                        count_waiter(&mut table, id, n, z, false);
                    }
                    count_waiter(&mut table, id, num, zero, true);
                    waits = Some((num, zero));
                }
                None
            }
        };
        if r.is_some() {
            if let Some((n, z)) = waits.take() {
                count_waiter(&mut table, id, n, z, false);
            }
        }
        r
    };
    let r = match step() {
        Some(r) => r,
        None if deadline.is_some_and(|d| d <= rk_frame::time::ticks()) => {
            let mut table = TABLE.lock();
            if let Some((n, z)) = waits.take() {
                count_waiter(&mut table, id, n, z, false);
            }
            Err(Errno::EAGAIN)
        }
        None => {
            let r = WAIT.wait_until_timeout(deadline.unwrap_or(u64::MAX), &mut step);
            if r.is_none() {
                let mut table = TABLE.lock();
                if let Some((n, z)) = waits.take() {
                    count_waiter(&mut table, id, n, z, false);
                }
            }
            r.unwrap_or(Err(Errno::EAGAIN))
        }
    };
    if r.is_ok() {
        WAIT.wake_all();
    }
    r.map(|()| 0)
}

pub(crate) fn semctl(cx: &Cx<'_>, id: u64, num: u64, cmd: u64, arg: u64) -> SysResult {
    let cmd = cmd as u32 & !IPC_64;
    let id = id as i32;
    let num = num as i32;
    let mut table = TABLE.lock();
    match cmd {
        IPC_INFO | SEM_INFO => {
            let mut info = SemInfo {
                semmap: SEMMNS,
                semmni: SEMMNI as i32,
                semmns: SEMMNS,
                semmnu: SEMMNS,
                semmsl: SEMMSL,
                semopm: SEMOPM as i32,
                semume: SEMOPM as i32,
                semusz: 20,
                semvmx: SEMVMX,
                semaem: SEMAEM,
            };
            if cmd == SEM_INFO {
                info.semusz = table.sets.len() as i32;
                info.semaem = table.sets.values().map(|s| s.members.len() as i32).sum();
            }
            let max = table.sets.keys().next_back().copied().unwrap_or(0);
            drop(table);
            cx.write_val(arg, &info)?;
            Ok(max as u64)
        }
        IPC_STAT | SEM_STAT | SEM_STAT_ANY => {
            let ds = table.get(id)?.ds();
            drop(table);
            cx.write_val(arg, &ds)?;
            Ok(if cmd == IPC_STAT { 0 } else { id as u64 })
        }
        IPC_SET => {
            table.get(id)?;
            drop(table);
            let ds: SemidDs = cx.read_val(arg)?;
            let mut table = TABLE.lock();
            let s = table.get(id)?;
            s.perm.uid = ds.perm.uid;
            s.perm.gid = ds.perm.gid;
            s.perm.mode = (s.perm.mode & !0o777) | (ds.perm.mode & 0o777);
            s.ctime = now();
            Ok(0)
        }
        IPC_RMID => {
            table.get(id)?;
            table.sets.remove(&id);
            table.undo.retain(|(_, set), _| *set != id);
            drop(table);
            // The waiters see that the set is gone and give `EIDRM`.
            WAIT.wake_all();
            Ok(0)
        }
        GETVAL | GETPID | GETNCNT | GETZCNT => {
            let s = table.get(id)?;
            let sem =
                usize::try_from(num).ok().and_then(|n| s.members.get(n)).ok_or(Errno::EINVAL)?;
            Ok(match cmd {
                GETVAL => sem.val as u64,
                GETPID => sem.pid as u64,
                GETNCNT => u64::from(sem.ncnt),
                _ => u64::from(sem.zcnt),
            })
        }
        GETALL => {
            let vals: Vec<u16> = table.get(id)?.members.iter().map(|s| s.val as u16).collect();
            drop(table);
            cx.write_bytes(arg, vals.as_bytes())?;
            Ok(0)
        }
        SETVAL => {
            let val = arg as i32;
            let s = table.get(id)?;
            let n =
                usize::try_from(num).ok().filter(|&n| n < s.members.len()).ok_or(Errno::EINVAL)?;
            if !(0..=SEMVMX).contains(&val) {
                return Err(Errno::ERANGE);
            }
            s.members[n].val = val;
            s.members[n].pid = pid(cx);
            s.ctime = now();
            table.clear_undo(id, Some(n));
            drop(table);
            WAIT.wake_all();
            Ok(0)
        }
        SETALL => {
            let len = table.get(id)?.members.len();
            drop(table);
            let bytes = cx.read_bytes(arg, len * 2)?;
            let vals: Vec<u16> =
                bytes.chunks_exact(2).map(|c| u16::from_ne_bytes([c[0], c[1]])).collect();
            if vals.iter().any(|&v| i32::from(v) > SEMVMX) {
                return Err(Errno::ERANGE);
            }
            let mut table = TABLE.lock();
            let s = table.get(id)?;
            if s.members.len() != len {
                return Err(Errno::EIDRM);
            }
            let pid = pid(cx);
            for (sem, v) in s.members.iter_mut().zip(vals) {
                sem.val = i32::from(v);
                sem.pid = pid;
            }
            s.ctime = now();
            table.clear_undo(id, None);
            drop(table);
            WAIT.wake_all();
            Ok(0)
        }
        _ => Err(Errno::EINVAL),
    }
}

/// Does the changes that `SEM_UNDO` recorded for the process `pid`, when it ends, as `exit_sem`
/// of Linux. A value stays in `0..=SEMVMX`.
pub(crate) fn exit(pid: i32) {
    let mut table = TABLE.lock();
    let ids: Vec<i32> =
        table.undo.range((pid, i32::MIN)..=(pid, i32::MAX)).map(|((_, id), _)| *id).collect();
    if ids.is_empty() {
        return;
    }
    for id in ids {
        let Some(adj) = table.undo.remove(&(pid, id)) else { continue };
        let Some(set) = table.sets.get_mut(&id) else { continue };
        for (sem, a) in set.members.iter_mut().zip(adj) {
            if a != 0 {
                sem.val = (sem.val + a).clamp(0, SEMVMX);
                sem.pid = pid;
            }
        }
        set.otime = now();
    }
    drop(table);
    WAIT.wake_all();
}
