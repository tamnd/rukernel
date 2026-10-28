//! The shared memory of System V: `shmget`, `shmat`, `shmdt` and `shmctl`, from ipc/shm.c.
//!
//! A segment is a set of pages in memory. Each page is zero at the first access. All the
//! mappings of a segment share its pages. `/proc/PID/maps` shows a mapping as
//! `/SYSV%08x (deleted)`, with the key of the segment, as in Linux.
//!
//! The number of attaches is the number of areas that hold the segment. An area that `mprotect`
//! splits counts two times. `IPC_RMID` removes the key at once, and the segment goes when the
//! last area goes.
//!
//! The calls check the permissions of a segment as `ipcperms` of Linux, and only the owner, the
//! creator or a process with `CAP_SYS_ADMIN` can change or remove a segment.

use crate::cx::{Cx, SysResult};
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_frame::mm::Frame;
use rk_frame::sync::SpinLock;
use rk_mm::vma::Backing;
use rk_mm::{MmFile, MmapRequest, PAGE_SIZE, Prot, VmaKind};
use rk_vfs::cred::{IpcOwner, cap};
use rk_vfs::ipc::{SHM_NEXT_ID, SHMALL, SHMMAX, SHMMNI};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// The key that always makes a new segment.
const IPC_PRIVATE: i32 = 0;
/// The flags of `shmget`.
const IPC_CREAT: u32 = 0o1000;
const IPC_EXCL: u32 = 0o2000;
/// The flags of `shmat`.
const SHM_RDONLY: u32 = 0o10000;
const SHM_RND: u32 = 0o20000;
const SHM_REMAP: u32 = 0o40000;
const SHM_EXEC: u32 = 0o100000;
/// The commands of `shmctl`.
const IPC_RMID: u32 = 0;
const IPC_SET: u32 = 1;
const IPC_STAT: u32 = 2;
const IPC_INFO: u32 = 3;
const SHM_LOCK: u32 = 11;
const SHM_UNLOCK: u32 = 12;
const SHM_STAT: u32 = 13;
const SHM_INFO: u32 = 14;
const SHM_STAT_ANY: u32 = 15;
/// The bit of the command that asks for the 64-bit structures. They are the only structures.
const IPC_64: u32 = 0x100;
/// The bits of the mode that tell that the segment has no key and that it is locked.
const SHM_DEST: u16 = 0o1000;
const SHM_LOCKED: u16 = 0o2000;

/// The smallest size of a segment, as `SHMMIN` of Linux. The sysctl files have the other limits.
const SHMMIN: u64 = 1;

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

/// The state of a segment, as `struct shmid64_ds` of x86-64.
#[derive(Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
struct ShmidDs {
    perm: IpcPerm,
    segsz: u64,
    atime: i64,
    dtime: i64,
    ctime: i64,
    cpid: i32,
    lpid: i32,
    nattch: u64,
    unused: [u64; 2],
}

/// The limits, as `struct shminfo64`.
#[derive(Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
struct ShmInfo64 {
    shmmax: u64,
    shmmin: u64,
    shmmni: u64,
    shmseg: u64,
    shmall: u64,
    unused: [u64; 4],
}

/// The use of the segments, as `struct shm_info`.
#[derive(Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
struct ShmUse {
    used_ids: i32,
    pad: u32,
    shm_tot: u64,
    shm_rss: u64,
    shm_swp: u64,
    swap_attempts: u64,
    swap_successes: u64,
}

/// The pages of a segment.
struct ShmPages {
    key: i32,
    id: i32,
    size: u64,
    pages: SpinLock<BTreeMap<u64, Arc<Frame>>>,
}

impl MmFile for ShmPages {
    fn page(&self, index: u64) -> Result<Arc<Frame>, Errno> {
        if index.checked_mul(PAGE_SIZE as u64).is_none_or(|o| o >= self.size) {
            return Err(Errno::EIO);
        }
        if let Some(frame) = self.pages.lock().get(&index) {
            return Ok(frame.clone());
        }
        let frame = Arc::new(rk_frame::mm::alloc_zeroed_frame().ok_or(Errno::ENOMEM)?);
        Ok(self.pages.lock().entry(index).or_insert(frame).clone())
    }

    fn name(&self) -> (u64, u64, Vec<u8>) {
        let path = alloc::format!("/SYSV{:08x} (deleted)", self.key as u32);
        (0, self.id as u64, path.into_bytes())
    }
}

/// A segment in the table.
struct Segment {
    pages: Arc<ShmPages>,
    perm: IpcPerm,
    atime: i64,
    dtime: i64,
    ctime: i64,
    cpid: i32,
    lpid: i32,
}

impl Segment {
    /// The number of areas that hold the segment.
    fn nattch(&self) -> u64 {
        Arc::strong_count(&self.pages) as u64 - 1
    }

    fn ds(&self) -> ShmidDs {
        ShmidDs {
            perm: self.perm,
            segsz: self.pages.size,
            atime: self.atime,
            dtime: self.dtime,
            ctime: self.ctime,
            cpid: self.cpid,
            lpid: self.lpid,
            nattch: self.nattch(),
            unused: [0; 2],
        }
    }
}

/// The segments by ID, and the next ID.
struct Table {
    segments: BTreeMap<i32, Segment>,
    next: i32,
}

impl Table {
    /// Drops the removed segments that no area holds.
    fn sweep(&mut self) {
        self.segments.retain(|_, s| s.perm.mode & SHM_DEST == 0 || s.nattch() > 0);
    }

    fn get(&mut self, id: i32) -> Result<&mut Segment, Errno> {
        self.sweep();
        self.segments.get_mut(&id).ok_or(Errno::EINVAL)
    }
}

static TABLE: SpinLock<Table> = SpinLock::new(Table { segments: BTreeMap::new(), next: 0 });

fn now() -> i64 {
    crate::info::realtime().sec
}

fn pid(cx: &Cx<'_>) -> i32 {
    cx.process().pid() as i32
}

pub(crate) fn shmget(cx: &Cx<'_>, key: u64, size: u64, flags: u64) -> SysResult {
    let key = key as i32;
    let flags = flags as u32;
    let c = cx.process().cred();
    let mut table = TABLE.lock();
    table.sweep();
    if key != IPC_PRIVATE {
        let found = table
            .segments
            .iter()
            .find(|(_, s)| s.perm.key == key && s.perm.mode & SHM_DEST == 0)
            .map(|(id, s)| (*id, s.pages.size, s.perm.owner()));
        if let Some((id, segsz, owner)) = found {
            if flags & (IPC_CREAT | IPC_EXCL) == IPC_CREAT | IPC_EXCL {
                return Err(Errno::EEXIST);
            }
            if size > segsz {
                return Err(Errno::EINVAL);
            }
            c.ipc_permission(&owner, flags & 0o777)?;
            return Ok(id as u64);
        }
        if flags & IPC_CREAT == 0 {
            return Err(Errno::ENOENT);
        }
    }
    if !(SHMMIN..=SHMMAX.get()).contains(&size) {
        return Err(Errno::EINVAL);
    }
    if table.segments.len() as u64 >= SHMMNI.get() as u64 {
        return Err(Errno::ENOSPC);
    }
    let next = table.next;
    let id = rk_vfs::ipc::alloc_id(&SHM_NEXT_ID, next, |id| table.segments.contains_key(&id));
    table.next = id.wrapping_add(1) & i32::MAX;
    let pages = Arc::new(ShmPages { key, id, size, pages: SpinLock::new(BTreeMap::new()) });
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
    let segment = Segment { pages, perm, atime: 0, dtime: 0, ctime: now(), cpid: pid(cx), lpid: 0 };
    table.segments.insert(id, segment);
    Ok(id as u64)
}

pub(crate) fn shmat(cx: &Cx<'_>, id: u64, addr: u64, flags: u64) -> SysResult {
    let flags = flags as u32;
    let mut addr = addr as usize;
    if addr % PAGE_SIZE != 0 {
        if flags & SHM_RND == 0 {
            return Err(Errno::EINVAL);
        }
        addr -= addr % PAGE_SIZE;
    }
    if flags & SHM_REMAP != 0 && addr == 0 {
        return Err(Errno::EINVAL);
    }
    let read_only = flags & SHM_RDONLY != 0;
    let mut access = if read_only { 0o444 } else { 0o666 };
    if flags & SHM_EXEC != 0 {
        access |= 0o111;
    }
    let c = cx.process().cred();
    let pages = {
        let mut table = TABLE.lock();
        let s = table.get(id as i32)?;
        c.ipc_permission(&s.perm.owner(), access)?;
        s.pages.clone()
    };
    let len = usize::try_from(pages.size.next_multiple_of(PAGE_SIZE as u64))
        .map_err(|_| Errno::ENOMEM)?;
    let prot = Prot { read: true, write: !read_only, exec: flags & SHM_EXEC != 0 };
    let file: Arc<dyn MmFile> = pages;
    let req = MmapRequest {
        addr,
        fixed: addr != 0,
        noreplace: addr != 0 && flags & SHM_REMAP == 0,
        shared: true,
        may_write: !read_only,
        file: Some((file, 0)),
        kind: VmaKind::Normal,
        ..MmapRequest::anon(len, prot)
    };
    let start = match cx.vm()?.mmap(req) {
        Err(Errno::EEXIST) => return Err(Errno::EINVAL),
        r => r?,
    };
    if let Ok(s) = TABLE.lock().get(id as i32) {
        s.atime = now();
        s.lpid = pid(cx);
    }
    Ok(start as u64)
}

pub(crate) fn shmdt(cx: &Cx<'_>, addr: u64) -> SysResult {
    let addr = addr as usize;
    if addr % PAGE_SIZE != 0 {
        return Err(Errno::EINVAL);
    }
    let vm = cx.vm()?;
    // The area at `addr` must be the start of a segment.
    let areas = vm.areas_in(addr, PAGE_SIZE).map_err(|_| Errno::EINVAL)?;
    let id = areas
        .iter()
        .find_map(|vma| match &vma.backing {
            Backing::File { file, offset: 0 } if vma.start == addr => {
                let (_, ino, path) = file.name();
                path.starts_with(b"/SYSV").then_some(ino as i32)
            }
            _ => None,
        })
        .ok_or(Errno::EINVAL)?;
    let size = TABLE.lock().segments.get(&id).map_or(PAGE_SIZE as u64, |s| s.pages.size);
    let len = usize::try_from(size.next_multiple_of(PAGE_SIZE as u64)).unwrap_or(PAGE_SIZE);
    vm.munmap(addr, len)?;
    let mut table = TABLE.lock();
    if let Some(s) = table.segments.get_mut(&id) {
        s.dtime = now();
        s.lpid = pid(cx);
    }
    table.sweep();
    Ok(0)
}

pub(crate) fn shmctl(cx: &Cx<'_>, id: u64, cmd: u64, buf: u64) -> SysResult {
    let cmd = cmd as u32 & !IPC_64;
    let id = id as i32;
    let c = cx.process().cred();
    // `IPC_SET` reads the new values before it finds the segment, as Linux.
    let new: Option<ShmidDs> = if cmd == IPC_SET { Some(cx.read_val(buf)?) } else { None };
    let mut table = TABLE.lock();
    match cmd {
        IPC_INFO => {
            let info = ShmInfo64 {
                shmmax: SHMMAX.get(),
                shmmin: SHMMIN,
                shmmni: SHMMNI.get() as u64,
                shmseg: SHMMNI.get() as u64,
                shmall: SHMALL.get(),
                unused: [0; 4],
            };
            table.sweep();
            let max = table.segments.keys().next_back().copied().unwrap_or(0);
            drop(table);
            cx.write_val(buf, &info)?;
            Ok(max as u64)
        }
        SHM_INFO => {
            table.sweep();
            let used = ShmUse {
                used_ids: table.segments.len() as i32,
                shm_tot: table
                    .segments
                    .values()
                    .map(|s| s.pages.size.div_ceil(PAGE_SIZE as u64))
                    .sum(),
                shm_rss: table.segments.values().map(|s| s.pages.pages.lock().len() as u64).sum(),
                ..ShmUse::default()
            };
            let max = table.segments.keys().next_back().copied().unwrap_or(0);
            drop(table);
            cx.write_val(buf, &used)?;
            Ok(max as u64)
        }
        IPC_STAT | SHM_STAT | SHM_STAT_ANY => {
            let s = table.get(id)?;
            if cmd != SHM_STAT_ANY {
                c.ipc_permission(&s.perm.owner(), 0o444)?;
            }
            let ds = s.ds();
            drop(table);
            cx.write_val(buf, &ds)?;
            Ok(if cmd == IPC_STAT { 0 } else { id as u64 })
        }
        IPC_SET => {
            let ds = new.ok_or(Errno::EINVAL)?;
            let s = table.get(id)?;
            if !c.ipc_owns(&s.perm.owner()) {
                return Err(Errno::EPERM);
            }
            // -1 is not a valid ID, as `ipc_update_perm` of Linux.
            if ds.perm.uid == u32::MAX || ds.perm.gid == u32::MAX {
                return Err(Errno::EINVAL);
            }
            s.perm.uid = ds.perm.uid;
            s.perm.gid = ds.perm.gid;
            s.perm.mode = (s.perm.mode & !0o777) | (ds.perm.mode & 0o777);
            s.ctime = now();
            Ok(0)
        }
        IPC_RMID => {
            let s = table.get(id)?;
            if !c.ipc_owns(&s.perm.owner()) {
                return Err(Errno::EPERM);
            }
            s.perm.mode |= SHM_DEST;
            s.perm.key = IPC_PRIVATE;
            table.sweep();
            Ok(0)
        }
        SHM_LOCK | SHM_UNLOCK => {
            let s = table.get(id)?;
            // Only the owner, the creator or a process with `CAP_IPC_LOCK` can lock a segment.
            if !c.capable(cap::IPC_LOCK) && c.euid != s.perm.uid && c.euid != s.perm.cuid {
                return Err(Errno::EPERM);
            }
            if cmd == SHM_LOCK {
                s.perm.mode |= SHM_LOCKED;
            } else {
                s.perm.mode &= !SHM_LOCKED;
            }
            Ok(0)
        }
        _ => Err(Errno::EINVAL),
    }
}

/// The text of `/proc/sysvipc/shm`, as `sysvipc_shm_proc_show` of Linux. The pages of a segment
/// are never on the swap device.
pub(crate) fn proc_text() -> Vec<u8> {
    let mut out = String::from(
        "       key      shmid perms                  size  cpid  lpid nattch   uid   gid  cuid  \
         cgid      atime      dtime      ctime                   rss                  swap\n",
    );
    let mut table = TABLE.lock();
    table.sweep();
    for (id, s) in &table.segments {
        let p = &s.perm;
        let rss = s.pages.pages.lock().len() as u64 * PAGE_SIZE as u64;
        out.push_str(&format!(
            "{:10} {:10}  {:4o} {:21} {:5} {:5}  {:5} {:5} {:5} {:5} {:5} {:10} {:10} {:10} {:21} \
             {:21}\n",
            p.key,
            id,
            p.mode,
            s.pages.size,
            s.cpid,
            s.lpid,
            s.nattch(),
            p.uid,
            p.gid,
            p.cuid,
            p.cgid,
            s.atime,
            s.dtime,
            s.ctime,
            rss,
            0,
        ));
    }
    out.into_bytes()
}
