//! The system calls of memory: `mmap`, `munmap`, `mprotect`, `brk` and `madvise`.

use crate::cx::{Cx, SysResult};
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_abi::native::mman::{
    MADV_DONTNEED, MAP_ANONYMOUS, MAP_FIXED, MAP_FIXED_NOREPLACE, MAP_PRIVATE, MAP_SHARED,
    MAP_SHARED_VALIDATE, MAP_TYPE, MREMAP_DONTUNMAP, MREMAP_FIXED, MREMAP_MAYMOVE, MS_ASYNC,
    MS_INVALIDATE, MS_SYNC,
};
use rk_frame::mm::Frame;
use rk_frame::sync::SpinLock;
use rk_mm::{MmFile, MmapRequest, PAGE_SIZE, Prot, Remap, VmaKind};
use rk_vfs::InodeRef;

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
/// `munmap` and the end of the address space write the dirty pages back. A `read` or `write` of
/// the file does not see the copies. The page cache of R2 replaces this type.
struct FilePages {
    inode: InodeRef,
    /// The path of the file when it was first mapped.
    path: Vec<u8>,
    pages: SpinLock<BTreeMap<u64, Arc<Frame>>>,
    /// The pages that a shared mapping changed. Lock it before `pages`.
    dirty: SpinLock<BTreeSet<u64>>,
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
        let mut buf = vec![0u8; PAGE_SIZE];
        let mut done = 0;
        while done < PAGE_SIZE {
            let n = self.inode.read_at(offset + done as u64, &mut buf[done..])?;
            if n == 0 {
                break;
            }
            done += n;
        }
        frame.write_bytes(0, &buf[..done]);
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
        }
        Ok(())
    }
}

/// The page cache of the files that a process mapped, so that two mappings of one file share
/// their pages.
static MAPPED: SpinLock<BTreeMap<usize, Arc<FilePages>>> = SpinLock::new(BTreeMap::new());

/// Gives the pages of `inode`, which has the path `path`. An entry stays while a mapping holds
/// it.
fn file_pages(inode: &InodeRef, path: Vec<u8>) -> Arc<FilePages> {
    let key = Arc::as_ptr(inode).cast::<()>() as usize;
    let mut map = MAPPED.lock();
    map.retain(|_, pages| Arc::strong_count(pages) > 1);
    map.entry(key)
        .or_insert_with(|| {
            let pages = SpinLock::new(BTreeMap::new());
            let dirty = SpinLock::new(BTreeSet::new());
            Arc::new(FilePages { inode: inode.clone(), path, pages, dirty })
        })
        .clone()
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
    let file = if flags & MAP_ANONYMOUS != 0 { None } else { Some(cx.file(fd)?) };
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
    let may_write = file.as_ref().is_none_or(|f| !shared || f.flags().writable());
    let file = match file {
        None => None,
        Some(file) => {
            let inode = file.inode().ok_or(Errno::ENODEV)?;
            let meta = inode.metadata();
            if !file.flags().readable() || (shared && prot.write && !file.flags().writable()) {
                return Err(Errno::EACCES);
            }
            match meta.file_type() {
                Some(rk_vfs::FileType::Regular) => {
                    let path =
                        file.location().map(rk_vfs::Location::absolute_path).unwrap_or_default();
                    let pages: Arc<dyn MmFile> = file_pages(inode, path);
                    Some((pages, offset))
                }
                // A mapping of /dev/zero is anonymous memory, as in Linux.
                Some(rk_vfs::FileType::CharDevice) if meta.rdev == DEV_ZERO => None,
                _ => return Err(Errno::ENODEV),
            }
        }
    };
    let req = MmapRequest {
        addr: addr as usize,
        len: len as usize,
        prot,
        shared,
        fixed: flags & MAP_FIXED != 0,
        noreplace: flags & MAP_FIXED_NOREPLACE != 0,
        low32: low32(flags),
        may_write,
        file,
        kind: VmaKind::Normal,
    };
    Ok(cx.vm()?.mmap(req)? as u64)
}

pub(crate) fn msync(cx: &Cx<'_>, addr: u64, len: u64, flags: u64) -> SysResult {
    let flags = flags as u32;
    if flags & !(MS_ASYNC | MS_INVALIDATE | MS_SYNC) != 0
        || flags & (MS_ASYNC | MS_SYNC) == MS_ASYNC | MS_SYNC
    {
        return Err(Errno::EINVAL);
    }
    // MS_ASYNC writes back at once too. MS_INVALIDATE has no work, because the mappings of a
    // file share one copy of each page.
    cx.vm()?.msync(addr as usize, len as usize)?;
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
    if addr as usize % PAGE_SIZE != 0 {
        return Err(Errno::EINVAL);
    }
    // `MADV_DONTNEED` gives zero pages again for anonymous memory. Each other advice is only a
    // hint, so it has no effect.
    if advice as u32 == MADV_DONTNEED && len != 0 {
        cx.vm()?.fill_zero(addr as usize, len as usize)?;
    }
    Ok(0)
}
