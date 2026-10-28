//! The system calls of memory: `mmap`, `munmap`, `mprotect`, `brk` and `madvise`.

use crate::cx::{Cx, SysResult};
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_abi::native::fcntl::{F_SEAL_FUTURE_WRITE, F_SEAL_WRITE};
use rk_abi::native::mman::{
    MADV_COLD, MADV_DODUMP, MADV_DOFORK, MADV_DONTDUMP, MADV_DONTFORK, MADV_DONTNEED,
    MADV_DONTNEED_LOCKED, MADV_FREE, MADV_GUARD_INSTALL, MADV_GUARD_REMOVE, MADV_HUGEPAGE,
    MADV_KEEPONFORK, MADV_MERGEABLE, MADV_NOHUGEPAGE, MADV_NORMAL, MADV_PAGEOUT,
    MADV_POPULATE_READ, MADV_POPULATE_WRITE, MADV_RANDOM, MADV_REMOVE, MADV_SEQUENTIAL,
    MADV_UNMERGEABLE, MADV_WILLNEED, MADV_WIPEONFORK, MAP_ANONYMOUS, MAP_FIXED,
    MAP_FIXED_NOREPLACE, MAP_GROWSDOWN, MAP_HUGE_SHIFT, MAP_HUGETLB, MAP_LOCKED, MAP_NONBLOCK,
    MAP_NORESERVE, MAP_POPULATE, MAP_PRIVATE, MAP_SHARED, MAP_SHARED_VALIDATE, MAP_TYPE,
    MCL_CURRENT, MCL_FUTURE, MCL_ONFAULT, MLOCK_ONFAULT, MREMAP_DONTUNMAP, MREMAP_FIXED,
    MREMAP_MAYMOVE, MS_ASYNC, MS_INVALIDATE, MS_SYNC,
};
use rk_frame::mm::Frame;
use rk_frame::sync::SpinLock;
use rk_mm::{Backing, HugeAdvice, MmFile, MmapRequest, PAGE_SIZE, Prot, Remap, VmaKind};
use rk_proc::limits::RLIMIT_MEMLOCK;
use rk_vfs::InodeRef;
use rk_vfs::cred::cap;

/// The flags of `mmap` that `MAP_SHARED_VALIDATE` accepts. Linux names the mask `LEGACY_MAP_MASK`.
/// It has the map type, `MAP_FIXED`, `MAP_ANONYMOUS`, `MAP_32BIT`, `MAP_GROWSDOWN`,
/// `MAP_DENYWRITE`, `MAP_EXECUTABLE`, `MAP_LOCKED`, `MAP_NORESERVE`, `MAP_POPULATE`,
/// `MAP_NONBLOCK`, `MAP_STACK`, `MAP_HUGETLB`, `MAP_UNINITIALIZED` and the huge page size bits.
const KNOWN_FLAGS: u32 = 0xfc07_f973;

/// Tells if `flags` has `MAP_32BIT`. Only x86-64 has the flag.
#[cfg(target_arch = "x86_64")]
fn low32(flags: u32) -> bool {
    flags & rk_abi::native::mman::MAP_32BIT != 0
}

#[cfg(not(target_arch = "x86_64"))]
fn low32(_flags: u32) -> bool {
    false
}

/// The device number of `/dev/zero`.
const DEV_ZERO: u64 = rk_vfs::device::makedev(1, 5);

/// The pages of a regular file, for a file mapping.
///
/// Each page is a copy of the file data, which the first fault reads. All the mappings of the
/// file share the copies. A write through a shared mapping marks the page dirty, and `msync`,
/// `munmap` and the end of the address space write the dirty pages back. The VFS keeps the copies
/// the same as the file through `rk_vfs::mapped`: a `write` changes them, and a `read` first
/// writes back the dirty pages.
pub(crate) struct FilePages {
    inode: InodeRef,
    /// The path of the file when it was first mapped.
    path: Vec<u8>,
    pages: SpinLock<BTreeMap<u64, Arc<Frame>>>,
    /// The pages that a shared mapping changed. Lock it before `pages`.
    dirty: SpinLock<BTreeSet<u64>>,
    /// The pages of `dirty` that a write back wrote, and that no write fault changed after it.
    /// The pages stay in `dirty`, because a mapping in another address space can still write
    /// them without a fault. `/proc/kpageflags` shows these pages as clean.
    clean: SpinLock<BTreeSet<u64>>,
}

impl MmFile for FilePages {
    fn page(&self, index: u64) -> Result<Arc<Frame>, Errno> {
        if let Some(frame) = self.pages.lock().get(&index) {
            return Ok(frame.clone());
        }
        let offset = index.checked_mul(PAGE_SIZE as u64).ok_or(Errno::EIO)?;
        // A page that starts past the end of the file has no data. The fault then sends SIGBUS.
        if offset >= self.inode.metadata().size {
            return Err(Errno::EIO);
        }
        let frame = rk_frame::mm::alloc_zeroed_frame().ok_or(Errno::ENOMEM)?;
        frame.write_bytes(0, &self.read_page(offset)?);
        let frame = Arc::new(frame);
        Ok(self.pages.lock().entry(index).or_insert(frame).clone())
    }

    fn name(&self) -> (u64, u64, Vec<u8>) {
        let meta = self.inode.metadata();
        (meta.dev, meta.ino, self.path.clone())
    }

    fn writes_back(&self) -> bool {
        true
    }

    fn dirty(&self, index: u64) {
        self.dirty.lock().insert(index);
        self.clean.lock().remove(&index);
    }

    fn cached(&self, index: u64) -> bool {
        self.pages.lock().contains_key(&index)
    }

    fn write_back(&self, first: u64, end: u64) -> Result<(), Errno> {
        let pages: Vec<(u64, Arc<Frame>)> = {
            let dirty = self.dirty.lock();
            let pages = self.pages.lock();
            dirty.range(first..end).filter_map(|i| Some((*i, pages.get(i)?.clone()))).collect()
        };
        // A page past the end of the file does not change the file, as on Linux.
        let size = self.inode.metadata().size;
        let mut buf = vec![0u8; PAGE_SIZE];
        for (index, frame) in pages {
            let offset = index * PAGE_SIZE as u64;
            let Some(left) = size.checked_sub(offset).filter(|&l| l > 0) else { break };
            let len = PAGE_SIZE.min(usize::try_from(left).unwrap_or(PAGE_SIZE));
            frame.read_bytes(0, &mut buf[..len]);
            let mut done = 0;
            while done < len {
                let n = self.inode.write_at(offset + done as u64, &buf[done..len])?;
                if n == 0 {
                    return Err(Errno::EIO);
                }
                done += n;
            }
            self.clean.lock().insert(index);
        }
        Ok(())
    }
}

impl FilePages {
    /// Reads the page of the file at `offset`. The bytes past the end of the file are zero.
    fn read_page(&self, offset: u64) -> Result<Vec<u8>, Errno> {
        let mut buf = vec![0u8; PAGE_SIZE];
        let mut done = 0;
        while done < PAGE_SIZE {
            let n = self.inode.read_at(offset + done as u64, &mut buf[done..])?;
            if n == 0 {
                break;
            }
            done += n;
        }
        buf[done..].fill(0);
        Ok(buf)
    }

    /// The copies of the pages that have a byte from `start` to `end` of the file.
    fn copies(&self, start: u64, end: u64) -> Vec<(u64, Arc<Frame>)> {
        let first = start / PAGE_SIZE as u64;
        let last = end.div_ceil(PAGE_SIZE as u64);
        self.pages.lock().range(first..last).map(|(i, f)| (*i, f.clone())).collect()
    }
}

impl rk_vfs::mapped::Mapped for FilePages {
    fn wrote(&self, offset: u64, data: &[u8]) {
        let end = offset + data.len() as u64;
        for (index, frame) in self.copies(offset, end) {
            let page = index * PAGE_SIZE as u64;
            let from = offset.max(page);
            let to = end.min(page + PAGE_SIZE as u64);
            let at = (from - offset) as usize;
            frame.write_bytes((from - page) as usize, &data[at..at + (to - from) as usize]);
        }
    }

    fn changed(&self, start: u64, end: u64) {
        for (index, frame) in self.copies(start, end) {
            // A page that the file cannot give becomes zeros. A later access past the end of
            // the file then gets SIGBUS.
            let data =
                self.read_page(index * PAGE_SIZE as u64).unwrap_or_else(|_| vec![0; PAGE_SIZE]);
            frame.write_bytes(0, &data);
        }
    }

    fn zero(&self, start: u64, end: u64) {
        for (index, frame) in self.copies(start, end) {
            let page = index * PAGE_SIZE as u64;
            let from = start.max(page);
            let to = end.min(page + PAGE_SIZE as u64);
            frame.write_bytes((from - page) as usize, &vec![0u8; (to - from) as usize]);
        }
    }

    fn sync(&self, start: u64, end: u64) -> Result<(), Errno> {
        let first = start / PAGE_SIZE as u64;
        if self.dirty.lock().range(first..end.div_ceil(PAGE_SIZE as u64)).next().is_none() {
            return Ok(());
        }
        self.write_back(first, end.div_ceil(PAGE_SIZE as u64))
    }

    fn frame_dirty(&self, phys: u64) -> Option<bool> {
        let index = *self.pages.lock().iter().find(|(_, f)| f.addr().get() == phys)?.0;
        let dirty = self.dirty.lock().contains(&index);
        Some(dirty && !self.clean.lock().contains(&index))
    }
}

/// The page cache of the files that a process mapped, so that two mappings of one file share
/// their pages.
static MAPPED: SpinLock<BTreeMap<usize, Arc<FilePages>>> = SpinLock::new(BTreeMap::new());

/// Gives the pages of `inode`, which has the path `path`. An entry stays while a mapping holds
/// it.
pub(crate) fn file_pages(inode: &InodeRef, path: Vec<u8>) -> Arc<FilePages> {
    let key = Arc::as_ptr(inode).cast::<()>() as usize;
    let mut map = MAPPED.lock();
    map.retain(|_, pages| Arc::strong_count(pages) > 1);
    map.entry(key)
        .or_insert_with(|| {
            let pages = SpinLock::new(BTreeMap::new());
            let dirty = SpinLock::new(BTreeSet::new());
            let clean = SpinLock::new(BTreeSet::new());
            let pages = Arc::new(FilePages { inode: inode.clone(), path, pages, dirty, clean });
            let mapped: Arc<dyn rk_vfs::mapped::Mapped> = pages.clone();
            rk_vfs::mapped::register(inode, Arc::downgrade(&mapped));
            pages
        })
        .clone()
}

/// The token of the shared mappings that can write a file, by the address of the inode. Each
/// such mapping holds the token, so the file has one while the token lives, as
/// `i_mmap_writable` of Linux counts them.
static WRITERS: SpinLock<BTreeMap<usize, Weak<()>>> = SpinLock::new(BTreeMap::new());

/// The pages of a file in a shared mapping that can write it. It holds the token of `WRITERS`.
struct SharedWrite {
    pages: Arc<FilePages>,
    _token: Arc<()>,
}

impl SharedWrite {
    fn new(inode: &InodeRef, pages: Arc<FilePages>) -> Self {
        let key = Arc::as_ptr(inode).cast::<()>() as usize;
        let mut map = WRITERS.lock();
        map.retain(|_, token| token.strong_count() > 0);
        let token = map.get(&key).and_then(Weak::upgrade).unwrap_or_else(|| {
            let token = Arc::new(());
            map.insert(key, Arc::downgrade(&token));
            token
        });
        SharedWrite { pages, _token: token }
    }
}

impl MmFile for SharedWrite {
    fn page(&self, index: u64) -> Result<Arc<Frame>, Errno> {
        self.pages.page(index)
    }

    fn name(&self) -> (u64, u64, Vec<u8>) {
        self.pages.name()
    }

    fn writes_back(&self) -> bool {
        self.pages.writes_back()
    }

    fn dirty(&self, index: u64) {
        self.pages.dirty(index);
    }

    fn cached(&self, index: u64) -> bool {
        self.pages.cached(index)
    }

    fn write_back(&self, first: u64, end: u64) -> Result<(), Errno> {
        self.pages.write_back(first, end)
    }
}

/// Tells if a shared mapping that can write `inode` exists, as `mapping_writably_mapped` of
/// Linux.
pub(crate) fn writably_mapped(inode: &InodeRef) -> bool {
    let key = Arc::as_ptr(inode).cast::<()>() as usize;
    WRITERS.lock().get(&key).is_some_and(|token| token.strong_count() > 0)
}

pub(crate) fn mmap(
    cx: &Cx<'_>,
    addr: u64,
    len: u64,
    prot: u64,
    flags: u64,
    fd: u64,
    offset: u64,
) -> SysResult {
    let flags = flags as u32;
    // Linux looks up the descriptor before it checks the other arguments.
    let file = if flags & MAP_ANONYMOUS != 0 { None } else { Some(cx.fdget(fd)?) };
    let prot = Prot::from_bits(prot as u32).ok_or(Errno::EINVAL)?;
    let shared = match flags & MAP_TYPE {
        MAP_SHARED => true,
        MAP_PRIVATE => false,
        MAP_SHARED_VALIDATE => {
            if flags & !KNOWN_FLAGS != 0 {
                return Err(Errno::EOPNOTSUPP);
            }
            true
        }
        _ => return Err(Errno::EINVAL),
    };
    if len == 0 || offset as usize % PAGE_SIZE != 0 {
        return Err(Errno::EINVAL);
    }
    let mut may_write = file.as_ref().is_none_or(|f| !shared || f.flags().writable());
    let file = match file {
        None => None,
        Some(file) => {
            let inode = file.inode().ok_or(Errno::ENODEV)?;
            let meta = inode.metadata();
            if !file.flags().readable() || (shared && prot.write && !file.flags().writable()) {
                return Err(Errno::EACCES);
            }
            if shared && prot.write {
                rk_vfs::swap::check(&**inode)?;
            }
            // A file with a write seal has no shared mapping that can write, and a shared
            // mapping that reads cannot become writable, as `memfd_check_seals_mmap` of Linux.
            let write_seals = (F_SEAL_WRITE | F_SEAL_FUTURE_WRITE) as u32;
            if shared && inode.seals().is_some_and(|seals| seals & write_seals != 0) {
                if prot.write {
                    return Err(Errno::EPERM);
                }
                may_write = false;
            }
            let path = || file.location().map(rk_vfs::Location::absolute_path).unwrap_or_default();
            // A file of hugetlbfs gives its huge pages. `MAP_HUGETLB` is only for such a file or
            // for anonymous memory, as `ksys_mmap_pgoff` of Linux.
            let pages: Option<Arc<dyn MmFile>> =
                match (rk_fs_hugetlbfs::huge_file(inode), meta.file_type()) {
                    (Some(huge), _) => {
                        huge.set_path(path());
                        Some(huge)
                    }
                    _ if flags & MAP_HUGETLB != 0 => return Err(Errno::EINVAL),
                    (None, Some(rk_vfs::FileType::Regular)) => {
                        let pages = file_pages(inode, path());
                        Some(if shared && may_write {
                            Arc::new(SharedWrite::new(inode, pages))
                        } else {
                            pages
                        })
                    }
                    // A mapping of /dev/zero is anonymous memory, as in Linux.
                    (None, Some(rk_vfs::FileType::CharDevice)) if meta.rdev == DEV_ZERO => None,
                    _ => return Err(Errno::ENODEV),
                };
            pages.map(|p| (p, offset))
        }
    };
    let hugetlb = file.is_none() && flags & MAP_HUGETLB != 0;
    let huge_file = file.as_ref().is_some_and(|(f, _)| f.huge_file().is_some());
    if hugetlb {
        hugetlb_size(flags >> MAP_HUGE_SHIFT)?;
    }
    let req = MmapRequest {
        addr: addr as usize,
        len: len as usize,
        prot,
        shared,
        fixed: flags & MAP_FIXED != 0,
        noreplace: flags & MAP_FIXED_NOREPLACE != 0,
        low32: low32(flags),
        may_write,
        locked: flags & MAP_LOCKED != 0,
        populate: flags & MAP_POPULATE != 0,
        grows_down: flags & MAP_GROWSDOWN != 0,
        file,
        kind: VmaKind::Normal,
        noreserve: flags & MAP_NORESERVE != 0,
        hugetlb,
    };
    let vm = cx.vm()?;
    let at = vm.mmap(req)?;
    // A truncate of the file then removes its pages from this address space.
    if huge_file {
        rk_mm::hugetlb::track(&vm);
    }
    Ok(at as u64)
}

/// Checks the size of a huge page that the bits `log` of `MAP_HUGE_*`, `SHM_HUGE_*` or
/// `MFD_HUGE_*` give: 0 for the default, or 21 for 2 MiB, the only size of the pool.
///
/// # Errors
///
/// `EINVAL` for another size, as `hstate_sizelog` of Linux finds no pool for it.
pub(crate) fn hugetlb_size(log: u32) -> Result<(), Errno> {
    match log & 0x3f {
        0 | 21 => Ok(()),
        _ => Err(Errno::EINVAL),
    }
}

pub(crate) fn msync(cx: &Cx<'_>, addr: u64, len: u64, flags: u64) -> SysResult {
    let flags = flags as u32;
    if flags & !(MS_ASYNC | MS_INVALIDATE | MS_SYNC) != 0
        || flags & (MS_ASYNC | MS_SYNC) == MS_ASYNC | MS_SYNC
    {
        return Err(Errno::EINVAL);
    }
    // MS_ASYNC writes back at once too. MS_INVALIDATE has no work, because the mappings of a
    // file share one copy of each page. It only fails on a locked area.
    cx.vm()?.msync(addr as usize, len as usize, flags & MS_INVALIDATE != 0)?;
    Ok(0)
}

pub(crate) fn mremap(
    cx: &Cx<'_>,
    addr: u64,
    old_len: u64,
    new_len: u64,
    flags: u64,
    new_addr: u64,
) -> SysResult {
    let flags = flags as u32;
    if flags & !(MREMAP_MAYMOVE | MREMAP_FIXED | MREMAP_DONTUNMAP) != 0 {
        return Err(Errno::EINVAL);
    }
    let remap = Remap {
        may_move: flags & MREMAP_MAYMOVE != 0,
        fixed: flags & MREMAP_FIXED != 0,
        dont_unmap: flags & MREMAP_DONTUNMAP != 0,
        new_addr: new_addr as usize,
    };
    Ok(cx.vm()?.mremap(addr as usize, old_len as usize, new_len as usize, remap)? as u64)
}

/// `remap_file_pages`. Linux has no nonlinear mappings now. It maps the file of the shared area
/// again at the range, from the page `pgoff` of the file, as `remap_file_pages` in mm/mmap.c of
/// Linux.
///
/// # Errors
///
/// `EINVAL` for a `prot` that is not 0, a range that wraps, or a range that is not in one shared
/// mapping of a file.
pub(crate) fn remap_file_pages(
    cx: &Cx<'_>,
    start: u64,
    size: u64,
    prot: u64,
    pgoff: u64,
    flags: u64,
) -> SysResult {
    if prot != 0 {
        return Err(Errno::EINVAL);
    }
    let page = PAGE_SIZE as u64;
    let (start, size) = (start & !(page - 1), size & !(page - 1));
    let end = start.checked_add(size).filter(|&end| end > start).ok_or(Errno::EINVAL)?;
    pgoff.checked_add(size / page).ok_or(Errno::EINVAL)?;
    let offset = pgoff.checked_mul(page).ok_or(Errno::EINVAL)?;
    let (start, end) = (
        usize::try_from(start).map_err(|_| Errno::EINVAL)?,
        usize::try_from(end).map_err(|_| Errno::EINVAL)?,
    );
    let vm = cx.vm()?;
    // The range is in one shared area of a file, or in areas next to it with the same file and
    // the same flags.
    let areas = vm.areas_in(start, end - start).map_err(|_| Errno::EINVAL)?;
    let first = areas.first().ok_or(Errno::EINVAL)?;
    let Backing::File { file, .. } = &first.backing else { return Err(Errno::EINVAL) };
    if !first.shared {
        return Err(Errno::EINVAL);
    }
    let same = |v: &rk_mm::Vma<rk_mm::FileRef>| {
        matches!(&v.backing, Backing::File { file: f, .. } if Arc::ptr_eq(f, file))
            && v.prot == first.prot
            && v.shared
            && v.may_write == first.may_write
            && v.locked == first.locked
    };
    if !areas.iter().all(same) {
        return Err(Errno::EINVAL);
    }
    let (prot, may_write, locked, hugetlb) =
        (first.prot, first.may_write, first.locked, first.hugetlb);
    let file = file.clone();
    drop(areas);
    // The old map goes first, and the file can refuse the new map: a System V segment that
    // `IPC_RMID` removed goes with its last map, as `do_mmap` and `shm_mmap` of Linux.
    vm.munmap(start, end - start)?;
    file.reopen()?;
    // The new mapping has the access of the area, and `MAP_NONBLOCK` stops the populate.
    let req = MmapRequest {
        addr: start,
        len: end - start,
        prot,
        shared: true,
        fixed: true,
        noreplace: false,
        low32: false,
        may_write,
        locked,
        populate: flags as u32 & MAP_NONBLOCK == 0,
        grows_down: false,
        file: Some((file, offset)),
        kind: VmaKind::Normal,
        noreserve: false,
        hugetlb,
    };
    vm.mmap(req)?;
    Ok(0)
}

/// The most locked bytes of the caller, as `can_do_mlock` of Linux checks them: `None` if the
/// caller has `CAP_IPC_LOCK`. Gives `EPERM` if `RLIMIT_MEMLOCK` is 0 and the caller does not have
/// the capability.
fn lock_limit(cx: &Cx<'_>) -> Result<Option<usize>, Errno> {
    if cx.process().cred().capable(cap::IPC_LOCK) {
        return Ok(None);
    }
    let limit = cx.process().limit(RLIMIT_MEMLOCK).cur;
    if limit == 0 {
        return Err(Errno::EPERM);
    }
    // The limit counts whole pages, as Linux does.
    Ok(Some(usize::try_from(limit).unwrap_or(usize::MAX) & !(PAGE_SIZE - 1)))
}

pub(crate) fn mlock(cx: &Cx<'_>, addr: u64, len: u64) -> SysResult {
    let limit = lock_limit(cx)?;
    cx.vm()?.mlock(addr as usize, len as usize, true, false, limit)?;
    Ok(0)
}

pub(crate) fn mlock2(cx: &Cx<'_>, addr: u64, len: u64, flags: u64) -> SysResult {
    if flags & !u64::from(MLOCK_ONFAULT) != 0 {
        return Err(Errno::EINVAL);
    }
    let limit = lock_limit(cx)?;
    cx.vm()?.mlock(addr as usize, len as usize, true, flags != 0, limit)?;
    Ok(0)
}

pub(crate) fn munlock(cx: &Cx<'_>, addr: u64, len: u64) -> SysResult {
    cx.vm()?.mlock(addr as usize, len as usize, false, false, None)?;
    Ok(0)
}

pub(crate) fn mlockall(cx: &Cx<'_>, flags: u64) -> SysResult {
    if flags & !u64::from(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT) != 0
        || flags & u64::from(MCL_CURRENT | MCL_FUTURE) == 0
    {
        return Err(Errno::EINVAL);
    }
    let flags = flags as u32;
    let limit = lock_limit(cx)?;
    let vm = cx.vm()?;
    vm.mlock_all(
        true,
        flags & MCL_CURRENT != 0,
        flags & MCL_FUTURE != 0,
        flags & MCL_ONFAULT != 0,
        limit,
    )?;
    Ok(0)
}

pub(crate) fn munlockall(cx: &Cx<'_>) -> SysResult {
    cx.vm()?.mlock_all(false, true, false, false, None)?;
    Ok(0)
}

pub(crate) fn mincore(cx: &Cx<'_>, addr: u64, len: u64, vec: u64) -> SysResult {
    let pages = cx.vm()?.mincore(addr as usize, len as usize)?;
    cx.write_bytes(vec, &pages)?;
    Ok(0)
}

pub(crate) fn munmap(cx: &Cx<'_>, addr: u64, len: u64) -> SysResult {
    cx.vm()?.munmap(addr as usize, len as usize)?;
    Ok(0)
}

pub(crate) fn mprotect(cx: &Cx<'_>, addr: u64, len: u64, prot: u64) -> SysResult {
    let prot = Prot::from_bits(prot as u32).ok_or(Errno::EINVAL)?;
    cx.vm()?.mprotect(addr as usize, len as usize, prot)?;
    Ok(0)
}

pub(crate) fn brk(cx: &Cx<'_>, addr: u64) -> SysResult {
    Ok(cx.vm()?.brk(addr as usize) as u64)
}

pub(crate) fn madvise(cx: &Cx<'_>, addr: u64, len: u64, advice: u64) -> SysResult {
    let advice = u32::try_from(advice).map_err(|_| Errno::EINVAL)?;
    // There is no memory failure handler, so `MADV_HWPOISON` and `MADV_SOFT_OFFLINE` are not
    // known.
    let known = matches!(
        advice,
        MADV_NORMAL
            | MADV_RANDOM
            | MADV_SEQUENTIAL
            | MADV_WILLNEED
            | MADV_DONTNEED
            | MADV_FREE
            | MADV_REMOVE
            | MADV_DONTFORK
            | MADV_DOFORK
            | MADV_HUGEPAGE
            | MADV_NOHUGEPAGE
            | MADV_DONTDUMP
            | MADV_DODUMP
            | MADV_WIPEONFORK
            | MADV_KEEPONFORK
            | MADV_COLD
            | MADV_PAGEOUT
            | MADV_POPULATE_READ
            | MADV_POPULATE_WRITE
            | MADV_DONTNEED_LOCKED
            | MADV_MERGEABLE
            | MADV_UNMERGEABLE
            | MADV_GUARD_INSTALL
            | MADV_GUARD_REMOVE
    );
    if !known || addr as usize % PAGE_SIZE != 0 {
        return Err(Errno::EINVAL);
    }
    if len == 0 {
        return Ok(0);
    }
    let vm = cx.vm()?;
    let areas = vm.areas_in(addr as usize, len as usize)?;
    for vma in &areas {
        let anon = matches!(vma.backing, rk_mm::Backing::Anon);
        let bad = match advice {
            MADV_DONTNEED | MADV_REMOVE => vma.locked,
            MADV_FREE => vma.locked || vma.shared || !anon,
            MADV_WIPEONFORK => vma.shared || !anon,
            _ => false,
        };
        if bad || (advice == MADV_REMOVE && !vma.shared) {
            return Err(Errno::EINVAL);
        }
    }
    if matches!(advice, MADV_MERGEABLE | MADV_UNMERGEABLE) {
        let end = (addr as usize).saturating_add(len as usize).next_multiple_of(PAGE_SIZE);
        rk_mm::ksm::madvise(&vm, addr as usize, end, advice == MADV_MERGEABLE)?;
        return Ok(0);
    }
    // `MADV_DONTNEED` and `MADV_FREE` remove the frames, so anonymous memory gives zero pages
    // again. The advice for huge pages and for `fork` goes in the areas, as `madvise_update_vma`
    // of Linux. Each other advice is only a hint, so it has no effect.
    let (addr, len) = (addr as usize, len as usize);
    match advice {
        MADV_DONTNEED | MADV_DONTNEED_LOCKED | MADV_FREE => vm.discard(addr, len),
        MADV_HUGEPAGE => vm.set_huge_advice(addr, len, HugeAdvice::Huge)?,
        MADV_NOHUGEPAGE => vm.set_huge_advice(addr, len, HugeAdvice::NoHuge)?,
        MADV_DONTFORK => vm.set_fork_advice(addr, len, Some(true), None)?,
        MADV_DOFORK => vm.set_fork_advice(addr, len, Some(false), None)?,
        MADV_WIPEONFORK => vm.set_fork_advice(addr, len, None, Some(true))?,
        MADV_KEEPONFORK => vm.set_fork_advice(addr, len, None, Some(false))?,
        MADV_GUARD_INSTALL => vm.guard_install(addr, len)?,
        MADV_GUARD_REMOVE => vm.guard_remove(addr, len)?,
        _ => {}
    }
    Ok(0)
}

/// The commands of `membarrier(2)`, `MEMBARRIER_CMD_*`.
mod membarrier_cmd {
    pub(super) const QUERY: u64 = 0;
    pub(super) const GLOBAL: u64 = 1 << 0;
    pub(super) const GLOBAL_EXPEDITED: u64 = 1 << 1;
    pub(super) const REGISTER_GLOBAL_EXPEDITED: u64 = 1 << 2;
    pub(super) const PRIVATE_EXPEDITED: u64 = 1 << 3;
    pub(super) const REGISTER_PRIVATE_EXPEDITED: u64 = 1 << 4;
    pub(super) const PRIVATE_EXPEDITED_SYNC_CORE: u64 = 1 << 5;
    pub(super) const REGISTER_PRIVATE_EXPEDITED_SYNC_CORE: u64 = 1 << 6;
    pub(super) const GET_REGISTRATIONS: u64 = 1 << 9;
    /// The commands that `QUERY` gives. The commands for restartable sequences are not there,
    /// because rukernel has no `rseq(2)`.
    pub(super) const SUPPORTED: u64 = GLOBAL
        | GLOBAL_EXPEDITED
        | REGISTER_GLOBAL_EXPEDITED
        | PRIVATE_EXPEDITED
        | REGISTER_PRIVATE_EXPEDITED
        | PRIVATE_EXPEDITED_SYNC_CORE
        | REGISTER_PRIVATE_EXPEDITED_SYNC_CORE
        | GET_REGISTRATIONS;
}

/// `membarrier(2)`: makes each CPU do a full memory barrier. The kernel interrupts each other
/// CPU, so each command does the same work. A private command needs its registration first, as
/// Linux. The return from an interrupt makes the CPU fetch the instructions again, so the
/// commands also do the work of `SYNC_CORE`.
pub(crate) fn membarrier(cx: &mut Cx<'_>, cmd: u64, flags: u64, _cpu: u64) -> SysResult {
    use membarrier_cmd::*;
    if flags != 0 {
        return Err(Errno::EINVAL);
    }
    let process = cx.process();
    let registered = u64::from(process.membarrier());
    match cmd {
        QUERY => return Ok(SUPPORTED),
        GET_REGISTRATIONS => return Ok(registered),
        REGISTER_GLOBAL_EXPEDITED
        | REGISTER_PRIVATE_EXPEDITED
        | REGISTER_PRIVATE_EXPEDITED_SYNC_CORE => {
            process.add_membarrier(cmd as u32);
            return Ok(0);
        }
        PRIVATE_EXPEDITED if registered & REGISTER_PRIVATE_EXPEDITED == 0 => {
            return Err(Errno::EPERM);
        }
        PRIVATE_EXPEDITED_SYNC_CORE if registered & REGISTER_PRIVATE_EXPEDITED_SYNC_CORE == 0 => {
            return Err(Errno::EPERM);
        }
        GLOBAL | GLOBAL_EXPEDITED | PRIVATE_EXPEDITED | PRIVATE_EXPEDITED_SYNC_CORE => {}
        _ => return Err(Errno::EINVAL),
    }
    rk_frame::cpu::barrier_all();
    Ok(0)
}
