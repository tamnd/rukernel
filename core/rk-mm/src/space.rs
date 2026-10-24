//! The address space of a process.
//!
//! An `AddressSpace` has the areas of the process and its page table. A page gets a frame at the
//! first access, in `handle_fault`. A private page that two address spaces share after `fork` is
//! read only in both, and the first write copies it. This is copy on write.

use crate::vma::{Backing, PAGE_SIZE, Prot, Vma, VmaKind, VmaSet, is_page_aligned, page_up};
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_frame::addr::VirtAddr;
use rk_frame::mm::{Frame, alloc_zeroed_frame};
use rk_frame::sync::SpinLock;
use rk_frame::vm::{MapError, PageProt, USER_END, UserFault, VmSpace};

/// A file that a process can map. rk-vfs implements it, so rk-mm does not depend on rk-vfs, per
/// spec/23-package-layout.md section 23.2.
pub trait MmFile: Send + Sync {
    /// Gives the frame that holds the page `index` of the file. A write to the frame through a
    /// shared mapping changes the file.
    ///
    /// # Errors
    ///
    /// Gives `ENOMEM` if no frame is free, or an error of the file system.
    fn page(&self, index: u64) -> Result<Arc<Frame>, Errno>;

    /// The device, the inode number and the path of the file, as `/proc/PID/maps` shows them.
    fn name(&self) -> (u64, u64, Vec<u8>) {
        (0, 0, Vec::new())
    }

    /// Tells if the file keeps the pages that a shared mapping changes, and writes them back. A
    /// page of such a file is read only in a shared mapping until the first write, which calls
    /// [`MmFile::dirty`].
    fn writes_back(&self) -> bool {
        false
    }

    /// Records that a shared mapping changed the page `index`.
    fn dirty(&self, _index: u64) {}

    /// Writes the changed pages from `first` up to `end` back to the file.
    ///
    /// # Errors
    ///
    /// Gives an error of the file system.
    fn write_back(&self, _first: u64, _end: u64) -> Result<(), Errno> {
        Ok(())
    }
}

/// A file in an area.
pub type FileRef = Arc<dyn MmFile>;

impl core::fmt::Debug for dyn MmFile {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("MmFile")
    }
}

/// The memory of a shared anonymous area. Each address space that maps the area after `fork`
/// finds the same frames here, also for a page that no process touched before the `fork`. Linux
/// keeps this memory in a shmem file.
struct SharedAnon {
    pages: SpinLock<BTreeMap<u64, Arc<Frame>>>,
}

impl MmFile for SharedAnon {
    fn page(&self, index: u64) -> Result<Arc<Frame>, Errno> {
        let mut pages = self.pages.lock();
        if let Some(frame) = pages.get(&index) {
            return Ok(frame.clone());
        }
        let frame = anon_frame()?;
        pages.insert(index, frame.clone());
        Ok(frame)
    }

    fn name(&self) -> (u64, u64, Vec<u8>) {
        (0, 0, b"/dev/zero (deleted)".to_vec())
    }
}

/// The lowest address that `mmap` gives without `MAP_FIXED`. Linux names it `mmap_min_addr`.
pub const MMAP_MIN_ADDR: usize = 0x1_0000;
/// The end of the main stack.
pub const STACK_TOP: usize = USER_END;
/// The size of the main stack area. The `RLIMIT_STACK` default of Linux is 8 MiB.
pub const STACK_SIZE: usize = 8 << 20;
/// The most areas that an address space can have. Linux names it `vm.max_map_count`.
pub const MAX_MAP_COUNT: usize = 65530;
/// The range for `MAP_32BIT`, as in Linux on x86-64.
const LOW32: (usize, usize) = (0x4000_0000, 0x8000_0000);
/// The top of the `mmap` area. Linux puts it a gap of 128 MiB below the stack.
pub const MMAP_TOP: usize = STACK_TOP - (128 << 20);

/// The kind of access that caused a page fault.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    /// A read.
    Read,
    /// A write.
    Write,
    /// An instruction fetch.
    Exec,
}

/// The arguments of `mmap` after the system call checks them.
#[derive(Clone, Debug)]
pub struct MmapRequest {
    /// The address hint, or the address for `fixed`.
    pub addr: usize,
    /// The length in bytes. It is not 0.
    pub len: usize,
    /// The access.
    pub prot: Prot,
    /// `MAP_SHARED`.
    pub shared: bool,
    /// `MAP_FIXED`: replace each mapping at the address.
    pub fixed: bool,
    /// `MAP_FIXED_NOREPLACE`: use the address, or fail with `EEXIST`.
    pub noreplace: bool,
    /// `MAP_32BIT`: put the mapping in the range from 1 GiB to 2 GiB, as Linux does on x86-64.
    pub low32: bool,
    /// The area can get write access later. See [`Vma::may_write`].
    pub may_write: bool,
    /// The file and the page aligned offset, or `None` for anonymous memory.
    pub file: Option<(FileRef, u64)>,
    /// What the area is for.
    pub kind: VmaKind,
}

impl MmapRequest {
    /// An anonymous private mapping at the address that the kernel chooses.
    pub fn anon(len: usize, prot: Prot) -> Self {
        Self {
            addr: 0,
            len,
            prot,
            shared: false,
            fixed: false,
            noreplace: false,
            low32: false,
            may_write: true,
            file: None,
            kind: VmaKind::Normal,
        }
    }
}

/// The flags and the new address of an `mremap` call.
#[derive(Clone, Copy, Debug, Default)]
pub struct Remap {
    /// `MREMAP_MAYMOVE`: the area can move to a new address.
    pub may_move: bool,
    /// `MREMAP_FIXED`: move the area to `new_addr`, and replace each mapping there.
    pub fixed: bool,
    /// `MREMAP_DONTUNMAP`: keep the old area after the move, without its pages.
    pub dont_unmap: bool,
    /// The new address for `fixed`.
    pub new_addr: usize,
}

struct State {
    vmas: VmaSet<FileRef>,
    /// The start of the heap. `brk` cannot go below it.
    brk_start: usize,
    /// The end of the heap.
    brk: usize,
}

/// The address space of one process.
pub struct AddressSpace {
    vm: VmSpace,
    state: SpinLock<State>,
}

fn map_error(e: MapError) -> Errno {
    match e {
        MapError::BadAddress => Errno::EFAULT,
        MapError::Mapped => Errno::EEXIST,
        MapError::NoMemory => Errno::ENOMEM,
    }
}

/// The page permissions for an area. A private page that is not only in this address space is read
/// only, so a write to it is a fault that copies it. A page of a shared file mapping that writes
/// back is read only until the first write marks it dirty. `exclusive` tells that the page can be
/// writable.
fn page_prot(vma: &Vma<FileRef>, exclusive: bool) -> PageProt {
    let tracked = matches!(&vma.backing, Backing::File { file, .. } if file.writes_back());
    PageProt {
        readable: vma.prot.read,
        writable: vma.prot.write && ((vma.shared && !tracked) || exclusive),
        executable: vma.prot.exec,
    }
}

impl Drop for AddressSpace {
    fn drop(&mut self) {
        // The process ended or called execve. Its shared file mappings go back to their files.
        let st = self.state.lock();
        for vma in st.vmas.iter() {
            let _ = write_back(vma, vma.start, vma.end);
        }
    }
}

impl AddressSpace {
    /// Makes an empty address space. Gives `ENOMEM` if no frame is free for the page table.
    pub fn new() -> Result<Self, Errno> {
        let vm = VmSpace::new().ok_or(Errno::ENOMEM)?;
        let state = State { vmas: VmaSet::new(), brk_start: 0, brk: 0 };
        Ok(Self { vm, state: SpinLock::new(state) })
    }

    /// The page table.
    pub fn vm(&self) -> &VmSpace {
        &self.vm
    }

    /// Loads the page table, so the user code of the process can run.
    pub fn activate(&self) {
        self.vm.activate();
    }

    /// Gives a copy of the areas, in address order.
    pub fn areas(&self) -> Vec<Vma<FileRef>> {
        self.state.lock().vmas.iter().cloned().collect()
    }

    /// Sets the start of the heap. The ELF loader calls it with the end of the program.
    pub fn set_brk_start(&self, addr: usize) {
        let mut st = self.state.lock();
        st.brk_start = addr;
        st.brk = addr;
    }

    /// Makes a mapping and gives its address.
    ///
    /// # Errors
    ///
    /// `EINVAL` for a bad address or length, `EEXIST` for `MAP_FIXED_NOREPLACE` on a mapping, and
    /// `ENOMEM` when no range is free.
    pub fn mmap(&self, req: MmapRequest) -> Result<usize, Errno> {
        if req.len == 0 {
            return Err(Errno::EINVAL);
        }
        let len = page_up(req.len).filter(|&l| l <= USER_END).ok_or(Errno::ENOMEM)?;
        if let Some((_, offset)) = &req.file
            && !is_page_aligned(*offset as usize)
        {
            return Err(Errno::EINVAL);
        }
        let mut st = self.state.lock();
        let start = if req.fixed || req.noreplace {
            if !is_page_aligned(req.addr) || req.addr.checked_add(len).is_none_or(|e| e > USER_END)
            {
                return Err(Errno::EINVAL);
            }
            if st.vmas.overlaps(req.addr, req.addr + len) {
                if req.noreplace {
                    return Err(Errno::EEXIST);
                }
                self.unmap_locked(&mut st, req.addr, req.addr + len);
            }
            if st.vmas.len() >= MAX_MAP_COUNT {
                return Err(Errno::ENOMEM);
            }
            req.addr
        } else {
            if st.vmas.len() >= MAX_MAP_COUNT {
                return Err(Errno::ENOMEM);
            }
            let (bottom, top) = if req.low32 { LOW32 } else { (MMAP_MIN_ADDR, MMAP_TOP) };
            let hint = req.addr & !(PAGE_SIZE - 1);
            let hint_ok = hint >= MMAP_MIN_ADDR
                && hint
                    .checked_add(len)
                    .is_some_and(|e| e <= if req.low32 { top } else { USER_END })
                && !st.vmas.overlaps(hint, hint + len);
            if hint_ok { hint } else { st.vmas.find_gap(len, bottom, top).ok_or(Errno::ENOMEM)? }
        };
        let backing = match req.file {
            Some((file, offset)) => Backing::File { file, offset },
            None if req.shared => {
                let file: FileRef = Arc::new(SharedAnon { pages: SpinLock::new(BTreeMap::new()) });
                Backing::File { file, offset: 0 }
            }
            None => Backing::Anon,
        };
        st.vmas.insert(Vma {
            start,
            end: start + len,
            prot: req.prot,
            shared: req.shared,
            may_write: req.may_write,
            backing,
            kind: req.kind,
        });
        Ok(start)
    }

    fn unmap_locked(&self, st: &mut State, start: usize, end: usize) {
        for vma in st.vmas.remove_range(start, end) {
            for page in self.vm.mapped_pages(VirtAddr::new(vma.start), VirtAddr::new(vma.end)) {
                self.vm.unmap(page);
            }
            // munmap has no error for a failed write back, as on Linux.
            let _ = write_back(&vma, vma.start, vma.end);
        }
    }

    /// Writes the changed pages of the shared file mappings in `addr..addr + len` back to their
    /// files.
    ///
    /// # Errors
    ///
    /// `EINVAL` if `addr` is not page aligned, `ENOMEM` if a page of the range is not mapped, or
    /// an error of the file system.
    pub fn msync(&self, addr: usize, len: usize) -> Result<(), Errno> {
        if !is_page_aligned(addr) {
            return Err(Errno::EINVAL);
        }
        let end = page_up(len).and_then(|l| addr.checked_add(l)).ok_or(Errno::ENOMEM)?;
        if end > USER_END {
            return Err(Errno::ENOMEM);
        }
        let st = self.state.lock();
        for vma in st.vmas.iter().filter(|v| v.start < end && addr < v.end) {
            write_back(vma, addr, end)?;
        }
        if !st.vmas.covers(addr, end) {
            return Err(Errno::ENOMEM);
        }
        Ok(())
    }

    /// Removes the mappings in `addr..addr + len`.
    ///
    /// # Errors
    ///
    /// `EINVAL` if `addr` is not page aligned, `len` is 0 or the range is not in the user half.
    /// `ENOMEM` if the range is in the middle of an area and the split makes too many areas.
    pub fn munmap(&self, addr: usize, len: usize) -> Result<(), Errno> {
        let end = page_up(len)
            .and_then(|l| addr.checked_add(l))
            .filter(|&e| len != 0 && is_page_aligned(addr) && e <= USER_END)
            .ok_or(Errno::EINVAL)?;
        let mut st = self.state.lock();
        if st.vmas.len() >= MAX_MAP_COUNT
            && st.vmas.find(addr).is_some_and(|vma| vma.start < addr && end < vma.end)
        {
            return Err(Errno::ENOMEM);
        }
        self.unmap_locked(&mut st, addr, end);
        Ok(())
    }

    /// Changes the size of the area at `addr`, and can move it. Gives the new address.
    ///
    /// # Errors
    ///
    /// `EINVAL` for a bad address, length or flag, `EFAULT` if `addr..addr + old_len` is not in
    /// one area, and `ENOMEM` if the area cannot grow and cannot move.
    pub fn mremap(
        &self,
        addr: usize,
        old_len: usize,
        new_len: usize,
        remap: Remap,
    ) -> Result<usize, Errno> {
        if (remap.fixed && !remap.may_move)
            || (remap.dont_unmap && (!remap.may_move || old_len != new_len))
            || !is_page_aligned(addr)
        {
            return Err(Errno::EINVAL);
        }
        let old_len = page_up(old_len).ok_or(Errno::EINVAL)?;
        let new_len = page_up(new_len).filter(|&l| l != 0).ok_or(Errno::EINVAL)?;
        let mut st = self.state.lock();
        if remap.fixed {
            let to = remap.new_addr;
            let to_end = to.checked_add(new_len).filter(|&e| e <= USER_END);
            let Some(to_end) = to_end.filter(|_| is_page_aligned(to)) else {
                return Err(Errno::EINVAL);
            };
            if to < addr.saturating_add(old_len) && addr < to_end {
                return Err(Errno::EINVAL);
            }
            Self::resizable(&st, addr, old_len)?;
            self.unmap_locked(&mut st, to, to_end);
            return self.move_locked(&mut st, addr, old_len, new_len, to, remap.dont_unmap);
        }
        let end = Self::resizable(&st, addr, old_len)?;
        if old_len >= new_len && !remap.dont_unmap {
            self.unmap_locked(&mut st, addr + new_len, addr + old_len);
            return Ok(addr);
        }
        // Grow the area in place if the range after it is free.
        let new_end = addr.checked_add(new_len).filter(|&e| e <= USER_END);
        if let Some(new_end) = new_end.filter(|_| old_len != 0 && !remap.dont_unmap)
            && end == addr + old_len
            && !st.vmas.overlaps(end, new_end)
        {
            st.vmas.update_range(addr, end, |vma| vma.end = new_end);
            return Ok(addr);
        }
        if !remap.may_move {
            return Err(Errno::ENOMEM);
        }
        let to = st.vmas.find_gap(new_len, MMAP_MIN_ADDR, MMAP_TOP).ok_or(Errno::ENOMEM)?;
        self.move_locked(&mut st, addr, old_len, new_len, to, remap.dont_unmap)
    }

    /// Examines the old range of `mremap`, and gives the end of its area. An `old_len` of 0
    /// copies a shared area, as Linux does.
    fn resizable(st: &State, addr: usize, old_len: usize) -> Result<usize, Errno> {
        let vma = st.vmas.find(addr).ok_or(Errno::EFAULT)?;
        if old_len == 0 && !vma.shared {
            return Err(Errno::EINVAL);
        }
        if old_len > vma.end - addr {
            return Err(Errno::EFAULT);
        }
        Ok(vma.end)
    }

    /// Moves the pages in `addr..addr + old_len` to `to`, and makes the area at `to` with
    /// `new_len` bytes. The range at `to` is free.
    fn move_locked(
        &self,
        st: &mut State,
        addr: usize,
        old_len: usize,
        new_len: usize,
        to: usize,
        dont_unmap: bool,
    ) -> Result<usize, Errno> {
        let mut vma = match st.vmas.find(addr) {
            Some(v) if old_len == 0 => {
                let mut copy = v.clone();
                if let Backing::File { offset, .. } = &mut copy.backing {
                    *offset += (addr - v.start) as u64;
                }
                copy.start = addr;
                copy
            }
            _ => st.vmas.remove_range(addr, addr + old_len).pop().ok_or(Errno::EFAULT)?,
        };
        for page in self.vm.mapped_pages(VirtAddr::new(addr), VirtAddr::new(addr + old_len)) {
            let Some((frame, prot)) = self.vm.page(page) else { continue };
            self.vm.unmap(page);
            let off = page.get() - addr;
            if off < new_len {
                self.vm.map(VirtAddr::new(to + off), frame, prot).map_err(map_error)?;
            }
        }
        if dont_unmap {
            st.vmas.insert(Vma { start: addr, end: addr + old_len, ..vma.clone() });
        }
        vma.start = to;
        vma.end = to + new_len;
        st.vmas.insert(vma);
        Ok(to)
    }

    /// Changes the access of the mappings in `addr..addr + len`.
    ///
    /// # Errors
    ///
    /// `EINVAL` if `addr` is not page aligned, `ENOMEM` if a page of the range is not mapped, and
    /// `EACCES` for write access to an area that cannot get it.
    pub fn mprotect(&self, addr: usize, len: usize, prot: Prot) -> Result<(), Errno> {
        if !is_page_aligned(addr) {
            return Err(Errno::EINVAL);
        }
        let end = page_up(len).and_then(|l| addr.checked_add(l)).ok_or(Errno::ENOMEM)?;
        if end > USER_END {
            return Err(Errno::ENOMEM);
        }
        let mut st = self.state.lock();
        if !st.vmas.covers(addr, end) {
            return Err(Errno::ENOMEM);
        }
        if prot.write && st.vmas.iter().any(|v| v.start < end && addr < v.end && !v.may_write) {
            return Err(Errno::EACCES);
        }
        st.vmas.update_range(addr, end, |vma| vma.prot = prot);
        for page in self.vm.mapped_pages(VirtAddr::new(addr), VirtAddr::new(end)) {
            let Some(vma) = st.vmas.find(page.get()) else { continue };
            // A private page that gets write access stays read only, and the next write fault
            // makes it writable if this address space is its only user.
            self.vm.protect(page, page_prot(vma, false));
        }
        Ok(())
    }

    /// Moves the end of the heap to `addr`, and gives the new end. A bad value gives the old end,
    /// as Linux does.
    pub fn brk(&self, addr: usize) -> usize {
        let mut st = self.state.lock();
        let (Some(old_end), Some(new_end)) = (page_up(st.brk), page_up(addr)) else {
            return st.brk;
        };
        if addr < st.brk_start || st.brk_start == 0 || new_end > MMAP_TOP {
            return st.brk;
        }
        if new_end > old_end {
            if st.vmas.overlaps(old_end, new_end) {
                return st.brk;
            }
            st.vmas.insert(Vma::anon(old_end, new_end, Prot::RW, VmaKind::Heap));
        } else if new_end < old_end {
            self.unmap_locked(&mut st, new_end, old_end);
        }
        st.brk = addr;
        addr
    }

    /// Handles a page fault at `addr`.
    ///
    /// # Errors
    ///
    /// Gives `EFAULT` if no area contains the address or the area does not allow the access. The
    /// kernel then sends `SIGSEGV`. Gives `ENOMEM` if no frame is free. Gives the error of the
    /// file for a page that the file cannot give, such as a page past the end of the file. The
    /// kernel then sends `SIGBUS`.
    pub fn handle_fault(&self, addr: usize, access: Access) -> Result<(), Errno> {
        let st = self.state.lock();
        let vma = st.vmas.find(addr).ok_or(Errno::EFAULT)?;
        let allowed = match access {
            Access::Read => vma.prot.read || vma.prot.write || vma.prot.exec,
            Access::Write => vma.prot.write,
            Access::Exec => vma.prot.exec,
        };
        if !allowed {
            return Err(Errno::EFAULT);
        }
        let page = addr & !(PAGE_SIZE - 1);
        let at = VirtAddr::new(page);
        let write = access == Access::Write;
        match self.vm.page(at) {
            None => {
                let (frame, exclusive) = match &vma.backing {
                    Backing::Anon => (anon_frame()?, true),
                    Backing::File { file, offset } => {
                        let index = file_index(vma, *offset, page);
                        let frame = file.page(index)?;
                        if vma.shared {
                            if write {
                                file.dirty(index);
                            }
                            (frame, write)
                        } else if !write {
                            (frame, false)
                        } else {
                            (copy_frame(&frame)?, true)
                        }
                    }
                };
                self.vm.map(at, frame, page_prot(vma, exclusive)).map_err(map_error)
            }
            Some((frame, prot)) => {
                if !write || prot.writable {
                    // Another fault mapped the page, or the page allows the access now.
                    return Ok(());
                }
                // The first write to a page of a shared file mapping.
                if vma.shared {
                    if let Backing::File { file, offset } = &vma.backing {
                        file.dirty(file_index(vma, *offset, page));
                    }
                    drop(frame);
                    self.vm.protect(at, page_prot(vma, true));
                    return Ok(());
                }
                // A write to a private page that is read only: copy on write. The page table and
                // `frame` hold two references. A third reference is another address space or the
                // page cache.
                if Arc::strong_count(&frame) == 2 && !matches!(vma.backing, Backing::File { .. }) {
                    drop(frame);
                    self.vm.protect(at, page_prot(vma, true));
                    return Ok(());
                }
                let copy = copy_frame(&frame)?;
                drop(frame);
                self.vm.unmap(at);
                self.vm.map(at, copy, page_prot(vma, true)).map_err(map_error)
            }
        }
    }

    /// Makes the address space of a child of `fork`. A shared area maps the same frames. A
    /// private area maps the same frames read only in both address spaces, so the first write in
    /// either one copies the page.
    ///
    /// # Errors
    ///
    /// Gives `ENOMEM` if no frame is free for a page table.
    pub fn fork(&self) -> Result<Self, Errno> {
        let child = Self::new()?;
        let st = self.state.lock();
        for vma in st.vmas.iter() {
            for page in self.vm.mapped_pages(VirtAddr::new(vma.start), VirtAddr::new(vma.end)) {
                let Some((frame, prot)) = self.vm.page(page) else { continue };
                let prot = if vma.shared {
                    prot
                } else {
                    let ro = PageProt { writable: false, ..prot };
                    self.vm.protect(page, ro);
                    ro
                };
                child.vm.map(page, frame, prot).map_err(map_error)?;
            }
        }
        *child.state.lock() = State { vmas: st.vmas.clone(), brk_start: st.brk_start, brk: st.brk };
        Ok(child)
    }

    /// Copies user memory at `addr` to `buf`. A page that is not there yet gets its frame.
    ///
    /// # Errors
    ///
    /// Gives `EFAULT` if a byte of the range is not in an area that allows a read.
    pub fn read(&self, addr: usize, buf: &mut [u8]) -> Result<(), Errno> {
        let mut done = 0;
        while done < buf.len() {
            match self.vm.read(VirtAddr::new(addr + done), &mut buf[done..]) {
                Ok(()) => return Ok(()),
                Err(UserFault { addr: at, .. }) => {
                    self.fault_in(at, Access::Read)?;
                    done = at - addr;
                }
            }
        }
        Ok(())
    }

    /// Copies `buf` to user memory at `addr`. A page that is read only after `fork` is copied.
    ///
    /// # Errors
    ///
    /// Gives `EFAULT` if a byte of the range is not in an area that allows a write.
    pub fn write(&self, addr: usize, buf: &[u8]) -> Result<(), Errno> {
        let mut done = 0;
        while done < buf.len() {
            match self.vm.write(VirtAddr::new(addr + done), &buf[done..]) {
                Ok(()) => return Ok(()),
                Err(UserFault { addr: at, .. }) => {
                    self.fault_in(at, Access::Write)?;
                    done = at - addr;
                }
            }
        }
        Ok(())
    }

    /// Fills `len` bytes of user memory at `addr` with zeros.
    ///
    /// # Errors
    ///
    /// As for `write`.
    pub fn fill_zero(&self, addr: usize, len: usize) -> Result<(), Errno> {
        let mut done = 0;
        while done < len {
            match self.vm.fill_zero(VirtAddr::new(addr + done), len - done) {
                Ok(()) => return Ok(()),
                Err(UserFault { addr: at, .. }) => {
                    self.fault_in(at, Access::Write)?;
                    done = at - addr;
                }
            }
        }
        Ok(())
    }

    /// Reads a string that ends with a zero byte, without the zero byte.
    ///
    /// # Errors
    ///
    /// Gives `EFAULT` for a bad address, and `ENAMETOOLONG` if no zero byte is in the first `max`
    /// bytes.
    pub fn read_cstr(&self, addr: usize, max: usize) -> Result<Vec<u8>, Errno> {
        let mut out = Vec::new();
        let mut at = addr;
        while out.len() < max {
            // Read up to the end of the page, so a string at the end of an area works.
            let n = (PAGE_SIZE - at % PAGE_SIZE).min(max - out.len());
            let mut chunk = [0u8; PAGE_SIZE];
            self.read(at, &mut chunk[..n])?;
            if let Some(zero) = chunk[..n].iter().position(|&b| b == 0) {
                out.extend_from_slice(&chunk[..zero]);
                return Ok(out);
            }
            out.extend_from_slice(&chunk[..n]);
            at += n;
        }
        Err(Errno::ENAMETOOLONG)
    }

    /// Gives the physical address of `addr` if it is in a shared area, else `None`. A futex in a
    /// shared area uses the physical address as its key, so that each address space that maps the
    /// page finds the same futex. A page that is not there yet gets its frame.
    ///
    /// # Errors
    ///
    /// Gives `EFAULT` if `addr` is not in an area that allows a read.
    pub fn shared_phys(&self, addr: usize) -> Result<Option<u64>, Errno> {
        let shared = match self.state.lock().vmas.find(addr) {
            Some(vma) if vma.prot.read => vma.shared,
            _ => return Err(Errno::EFAULT),
        };
        if !shared {
            return Ok(None);
        }
        self.fault_in(addr, Access::Read)?;
        let page = VirtAddr::new(addr & !(PAGE_SIZE - 1));
        let (frame, _) = self.vm.page(page).ok_or(Errno::EFAULT)?;
        Ok(Some(frame.addr().get() + (addr & (PAGE_SIZE - 1)) as u64))
    }

    fn fault_in(&self, addr: usize, access: Access) -> Result<(), Errno> {
        // A copy gives EFAULT also for a page that would be SIGBUS, as on Linux.
        self.handle_fault(addr, access).map_err(|e| match e {
            Errno::ENOMEM => e,
            _ => Errno::EFAULT,
        })?;
        let page = VirtAddr::new(addr & !(PAGE_SIZE - 1));
        match self.vm.page(page) {
            Some((_, p)) if access != Access::Write || p.writable => Ok(()),
            _ => Err(Errno::EFAULT),
        }
    }
}

/// The index in the file of the page at `page` in `vma`, which maps the file from `offset`.
fn file_index(vma: &Vma<FileRef>, offset: u64, page: usize) -> u64 {
    (offset + (page - vma.start) as u64) / PAGE_SIZE as u64
}

/// Writes back the shared file pages of `vma` from `start` up to `end`.
fn write_back(vma: &Vma<FileRef>, start: usize, end: usize) -> Result<(), Errno> {
    match &vma.backing {
        Backing::File { file, offset } if vma.shared && file.writes_back() => {
            let start = start.max(vma.start);
            let end = end.min(vma.end);
            if start >= end {
                return Ok(());
            }
            file.write_back(file_index(vma, *offset, start), file_index(vma, *offset, end))
        }
        _ => Ok(()),
    }
}

fn anon_frame() -> Result<Arc<Frame>, Errno> {
    alloc_zeroed_frame().map(Arc::new).ok_or(Errno::ENOMEM)
}

fn copy_frame(from: &Frame) -> Result<Arc<Frame>, Errno> {
    let frame = rk_frame::mm::alloc_frame().ok_or(Errno::ENOMEM)?;
    frame.copy_from(from);
    Ok(Arc::new(frame))
}
