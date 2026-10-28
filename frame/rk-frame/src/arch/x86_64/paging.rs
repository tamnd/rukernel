//! The kernel page tables on x86-64.
//!
//! The layout is the layout of Linux with 4 level paging and no KASLR, per
//! Documentation/arch/x86/x86_64/mm.rst in the Linux tree:
//!
//! | Start                | Contents                                   |
//! |----------------------|--------------------------------------------|
//! | `0xffff888000000000` | The direct map of physical memory          |
//! | `0xffffc90000000000` | The vmalloc range                          |
//! | `0xffffffff80000000` | The kernel image                           |
//!
//! The direct map uses 2 MiB pages and covers the RAM in the memory map. The kernel image uses
//! 4 KiB pages, so that each section has its own permissions: text is read only and executable,
//! rodata is read only, and data and bss are writable. Nothing is writable and executable.

use super::cpu::{self, MAX_CPUS};
use crate::addr::PAGE_SIZE;
use crate::boot::{BootInfo, MemoryKind};
use crate::mm::PageInfo;
use crate::mm::frame::{alloc_table_frame, free_frame_phys};
use crate::sync::SpinLock;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// The start of the direct map. Linux names it `PAGE_OFFSET`.
pub(crate) const PAGE_OFFSET: usize = 0xffff_8880_0000_0000;
/// The start of the vmalloc range. Linux names it `VMALLOC_START`.
pub(crate) const VMALLOC_START: usize = 0xffff_c900_0000_0000;
/// The end of the vmalloc range.
pub(crate) const VMALLOC_END: usize = 0xffff_e8ff_ffff_ffff;
/// The heap range is the last 4 TiB of the vmalloc range. `vmap` uses the addresses below it.
pub(crate) const HEAP_START: usize = 0xffff_e500_0000_0000;
/// The end of the heap range.
pub(crate) const HEAP_END: usize = 0xffff_e900_0000_0000;
/// The virtual address of the kernel image at physical address 0.
pub(crate) const KERNEL_BASE: usize = 0xffff_ffff_8000_0000;
/// The physical address of the start of the kernel image, with the boot code. x86_64.ld has the
/// same value. Linux names it `CONFIG_PHYSICAL_START`.
const KERNEL_PHYS: u64 = 0x100_0000;

/// The boot page tables map physical memory below this address at address 0.
const BOOT_IDENTITY_LIMIT: u64 = 1 << 30;

const PRESENT: u64 = 1 << 0;
const WRITABLE: u64 = 1 << 1;
const USER: u64 = 1 << 2;
const WRITE_THROUGH: u64 = 1 << 3;
const NO_CACHE: u64 = 1 << 4;
const HUGE: u64 = 1 << 7;
const GLOBAL: u64 = 1 << 8;
const NO_EXECUTE: u64 = 1 << 63;
const ADDR_MASK: u64 = 0x000f_ffff_ffff_f000;

const HUGE_SIZE: u64 = 2 << 20;

/// The top level entries of the kernel half of the address space.
const KERNEL_HALF: core::ops::Range<usize> = 256..512;

unsafe extern "C" {
    static __text_start: u8;
    static __text_end: u8;
    static __rodata_end: u8;
    static __kernel_end: u8;
}

fn sym(s: *const u8) -> usize {
    s as usize
}

/// The physical address range of the kernel image, with the boot code and the boot page tables.
pub(crate) fn kernel_phys() -> core::ops::Range<u64> {
    KERNEL_PHYS..(sym(&raw const __kernel_end) - KERNEL_BASE) as u64
}

/// The virtual address range of the kernel image.
pub(crate) fn kernel_image() -> (usize, usize) {
    (sym(&raw const __text_start), sym(&raw const __kernel_end))
}

/// The virtual address range of the code of the kernel.
pub(crate) fn kernel_text() -> core::ops::Range<usize> {
    sym(&raw const __text_start)..sym(&raw const __text_end)
}

/// The direct map is in use. Before that, the boot identity map is in use.
static DIRECT_MAP: AtomicBool = AtomicBool::new(false);
/// The physical address of the top level table of the kernel.
static KERNEL_PML4: AtomicU64 = AtomicU64::new(0);
/// Changes to the kernel page tables take this lock.
static TABLES: SpinLock<()> = SpinLock::new(());

/// Gives a kernel virtual address for a physical address.
///
/// # Panics
///
/// Before the direct map is in use, if the address is outside the boot identity map.
pub(crate) fn phys_to_virt(phys: u64) -> usize {
    if DIRECT_MAP.load(Ordering::Acquire) {
        PAGE_OFFSET + phys as usize
    } else {
        assert!(phys < BOOT_IDENTITY_LIMIT, "{phys:#x} is outside the boot identity map");
        phys as usize
    }
}

/// The address of the entry `index` of the table at physical address `table`.
fn entry(table: u64, index: usize) -> *mut u64 {
    (phys_to_virt(table) as *mut u64).wrapping_add(index)
}

fn read_entry(table: u64, index: usize) -> u64 {
    // SAFETY: `table` is the physical address of a page table that the kernel made, the index is
    // less than 512, and `phys_to_virt` maps it.
    unsafe { entry(table, index).read_volatile() }
}

fn write_entry(table: u64, index: usize, value: u64) {
    // SAFETY: as for `read_entry`. The caller holds the `TABLES` lock, or the tables are not in
    // use yet.
    unsafe { entry(table, index).write_volatile(value) };
}

/// The table indexes of a virtual address, from the top level down.
fn indexes(virt: usize) -> [usize; 4] {
    [(virt >> 39) & 511, (virt >> 30) & 511, (virt >> 21) & 511, (virt >> 12) & 511]
}

/// Gives the next level table for an entry, and makes one if the entry is empty. `upper` is
/// `USER` for a user mapping and 0 for a kernel mapping.
fn next_table(table: u64, index: usize, upper: u64) -> Result<u64, ()> {
    let e = read_entry(table, index);
    if e & PRESENT != 0 {
        assert!(e & HUGE == 0, "a huge page is in the path of a 4 KiB mapping");
        assert!(e & USER == upper, "a user mapping and a kernel mapping share a table");
        return Ok(e & ADDR_MASK);
    }
    let new = alloc_table_frame().ok_or(())?;
    // The upper levels allow everything. The last level gives the permissions.
    write_entry(table, index, new | PRESENT | WRITABLE | upper);
    Ok(new)
}

/// Gives the last level table for `virt`, and makes the tables that are not there.
fn leaf_table(pml4: u64, virt: usize, upper: u64) -> Result<u64, ()> {
    let [i4, i3, i2, _] = indexes(virt);
    let pdpt = next_table(pml4, i4, upper)?;
    let pd = next_table(pdpt, i3, upper)?;
    next_table(pd, i2, upper)
}

fn map_4k(pml4: u64, virt: usize, phys: u64, flags: u64) -> Result<(), ()> {
    let pt = leaf_table(pml4, virt, 0)?;
    write_entry(pt, indexes(virt)[3], phys | flags | PRESENT);
    Ok(())
}

fn map_2m(pml4: u64, virt: usize, phys: u64, flags: u64) -> Result<(), ()> {
    let [i4, i3, i2, _] = indexes(virt);
    let pdpt = next_table(pml4, i4, 0)?;
    let pd = next_table(pdpt, i3, 0)?;
    write_entry(pd, i2, phys | flags | PRESENT | HUGE);
    Ok(())
}

/// Drops the TLB entry of `virt` on this CPU.
pub(crate) fn flush(virt: usize) {
    // SAFETY: invlpg only drops a TLB entry.
    unsafe { core::arch::asm!("invlpg [{}]", in(reg) virt, options(nostack, preserves_flags)) };
}

/// Drops all the TLB entries of user pages on this CPU. The kernel pages are global, so they stay.
pub(crate) fn flush_user_all() {
    // SAFETY: a write of the value that CR3 has now only drops the TLB entries that are not
    // global. The page tables do not change.
    unsafe {
        core::arch::asm!(
            "mov {0}, cr3",
            "mov cr3, {0}",
            out(reg) _,
            options(nostack, preserves_flags),
        );
    }
}

/// Makes the kernel page tables and loads them. After this, the boot identity map is gone.
pub(crate) fn init(info: &BootInfo) {
    let pml4 = alloc_table_frame().unwrap_or_else(|| panic!("no frame for the kernel page tables"));

    // The direct map: all RAM that the memory map gives, in 2 MiB pages. Physical address 0 to
    // 1 MiB is also in it, for the firmware tables.
    let ram = info.memory().iter().filter(|r| {
        matches!(
            r.kind,
            MemoryKind::Usable
                | MemoryKind::AcpiReclaimable
                | MemoryKind::AcpiNvs
                | MemoryKind::Persistent
        )
    });
    let first_mib = crate::boot::MemoryRegion {
        start: crate::addr::PhysAddr::new(0),
        len: 1 << 20,
        kind: MemoryKind::Reserved,
    };
    // The initramfs is in the direct map too, also if the memory map does not give it as RAM.
    let initrd = info.initrd().map(|(start, len)| crate::boot::MemoryRegion {
        start,
        len,
        kind: MemoryKind::Reserved,
    });
    for r in core::iter::once(&first_mib).chain(initrd.as_ref()).chain(ram) {
        // A 2 MiB page that two regions share is written two times with the same value.
        let start = r.start.get() / HUGE_SIZE * HUGE_SIZE;
        let end = (r.start.get() + r.len).div_ceil(HUGE_SIZE) * HUGE_SIZE;
        let mut p = start;
        while p < end {
            map_2m(pml4, PAGE_OFFSET + p as usize, p, WRITABLE | GLOBAL | NO_EXECUTE)
                .unwrap_or_else(|()| panic!("no frame for the direct map"));
            p += HUGE_SIZE;
        }
    }

    // The kernel image, with the permissions of each section.
    let text = sym(&raw const __text_start);
    let text_end = sym(&raw const __text_end);
    let rodata_end = sym(&raw const __rodata_end);
    let end = sym(&raw const __kernel_end);
    let mut v = text;
    while v < end {
        let flags = if v < text_end {
            GLOBAL
        } else if v < rodata_end {
            GLOBAL | NO_EXECUTE
        } else {
            WRITABLE | GLOBAL | NO_EXECUTE
        };
        map_4k(pml4, v, (v - KERNEL_BASE) as u64, flags)
            .unwrap_or_else(|()| panic!("no frame for the kernel image map"));
        v += PAGE_SIZE;
    }

    // Each top level entry of the kernel half points to a table now. A user address space copies
    // these entries, so a later kernel mapping is in each address space too.
    for i in KERNEL_HALF {
        next_table(pml4, i, 0).unwrap_or_else(|()| panic!("no frame for the kernel page tables"));
    }

    KERNEL_PML4.store(pml4, Ordering::Release);
    // SAFETY: the new tables map the kernel image at the same virtual addresses as the boot
    // tables, so the code, the stack, the GDT, the IDT and the TSS stay at their addresses. Each
    // reference that the kernel holds now is to the kernel image. Nothing uses the identity map
    // after this point, because `DIRECT_MAP` changes before the next call to `phys_to_virt`.
    unsafe {
        core::arch::asm!(
            "mov rax, cr4",
            "or rax, 0x80",                 // CR4.PGE: the global bit works
            "mov cr4, rax",
            "mov cr3, {}",
            in(reg) pml4,
            out("rax") _,
            options(nostack),
        );
    }
    DIRECT_MAP.store(true, Ordering::Release);
    active().store(pml4, Ordering::Release);
}

/// Copies the kernel half of the kernel table to the top level table at the physical address
/// `table`.
pub(crate) fn copy_kernel_half(table: u64) {
    let kernel = KERNEL_PML4.load(Ordering::Acquire);
    for i in KERNEL_HALF {
        write_entry(table, i, read_entry(kernel, i));
    }
}

/// Maps one 4 KiB page of the vmalloc range.
pub(crate) fn map_page(virt: usize, phys: u64, writable: bool) -> Result<(), ()> {
    assert!((VMALLOC_START..VMALLOC_END).contains(&virt), "{virt:#x} is not in the vmalloc range");
    let _guard = TABLES.lock();
    let flags = GLOBAL | NO_EXECUTE | if writable { WRITABLE } else { 0 };
    map_4k(KERNEL_PML4.load(Ordering::Acquire), virt, phys, flags)
}

/// Maps one 4 KiB page of device registers in the vmalloc range. The page is writable and not
/// cached.
pub(crate) fn map_mmio_page(virt: usize, phys: u64) -> Result<(), ()> {
    assert!((VMALLOC_START..VMALLOC_END).contains(&virt), "{virt:#x} is not in the vmalloc range");
    let _guard = TABLES.lock();
    let flags = WRITABLE | WRITE_THROUGH | NO_CACHE | GLOBAL | NO_EXECUTE;
    map_4k(KERNEL_PML4.load(Ordering::Acquire), virt, phys, flags)
}

/// Removes the mapping of one 4 KiB page of the vmalloc range. Gives the physical address that
/// it mapped.
pub(crate) fn unmap_page(virt: usize) -> Option<u64> {
    assert!((VMALLOC_START..VMALLOC_END).contains(&virt), "{virt:#x} is not in the vmalloc range");
    let _guard = TABLES.lock();
    let mut table = KERNEL_PML4.load(Ordering::Acquire);
    let [i4, i3, i2, i1] = indexes(virt);
    for i in [i4, i3, i2] {
        let e = read_entry(table, i);
        if e & PRESENT == 0 || e & HUGE != 0 {
            return None;
        }
        table = e & ADDR_MASK;
    }
    let e = read_entry(table, i1);
    if e & PRESENT == 0 {
        return None;
    }
    write_entry(table, i1, 0);
    flush(virt);
    super::smp::shootdown(0, virt as u64);
    Some(e & ADDR_MASK)
}

/// The last level table and the index of the entry of `virt` in the kernel tables, if the tables
/// on the way are there. The caller holds the `TABLES` lock.
fn kernel_leaf(virt: usize) -> Option<(u64, usize)> {
    let mut table = KERNEL_PML4.load(Ordering::Acquire);
    let [i4, i3, i2, i1] = indexes(virt);
    for i in [i4, i3, i2] {
        let e = read_entry(table, i);
        if e & PRESENT == 0 || e & HUGE != 0 {
            return None;
        }
        table = e & ADDR_MASK;
    }
    Some((table, i1))
}

/// Removes the mappings of `pages` 4 KiB pages of the heap range from `virt`, with one TLB
/// shootdown for the range, as `flush_tlb_kernel_range` of Linux. Then `free` gets the physical
/// address of each page that was mapped. The heap does not use an address again, so no map comes
/// between the two steps.
pub(crate) fn unmap_pages(virt: usize, pages: usize, free: &mut dyn FnMut(u64)) {
    if pages == 0 {
        return;
    }
    let end = virt + pages * PAGE_SIZE;
    assert!(HEAP_START <= virt && end <= HEAP_END, "{virt:#x} is not in the heap range");
    let _guard = TABLES.lock();
    // First the entries lose their present bit and keep the address, so that each CPU stops the
    // use of the pages before the frames go back.
    for at in (virt..end).step_by(PAGE_SIZE) {
        if let Some((table, i)) = kernel_leaf(at) {
            let e = read_entry(table, i);
            if e & PRESENT != 0 {
                write_entry(table, i, e & !PRESENT);
                flush(at);
            }
        }
    }
    super::smp::shootdown_range(0, virt as u64, pages as u64);
    for at in (virt..end).step_by(PAGE_SIZE) {
        if let Some((table, i)) = kernel_leaf(at) {
            let e = read_entry(table, i);
            if e != 0 {
                write_entry(table, i, 0);
                free(e & ADDR_MASK);
            }
        }
    }
}

/// Walks the kernel page tables for one virtual address.
pub(crate) fn query(virt: usize) -> Option<PageInfo> {
    let pml4 = KERNEL_PML4.load(Ordering::Acquire);
    if pml4 == 0 {
        return None;
    }
    let mut table = pml4;
    let mut writable = true;
    let mut user = true;
    let mut executable = true;
    for (level, i) in indexes(virt).into_iter().enumerate() {
        let e = read_entry(table, i);
        if e & PRESENT == 0 {
            return None;
        }
        writable &= e & WRITABLE != 0;
        user &= e & USER != 0;
        executable &= e & NO_EXECUTE == 0;
        let page_size = match level {
            1 if e & HUGE != 0 => Some(1u64 << 30),
            2 if e & HUGE != 0 => Some(HUGE_SIZE),
            3 => Some(PAGE_SIZE as u64),
            _ => None,
        };
        if let Some(size) = page_size {
            let phys = (e & ADDR_MASK & !(size - 1)) + (virt as u64 & (size - 1));
            return Some(PageInfo {
                phys: crate::addr::PhysAddr::new(phys),
                writable,
                executable,
                user,
            });
        }
        table = e & ADDR_MASK;
    }
    None
}

/// The end of the user half of the address space. Linux names it `TASK_SIZE_MAX`. The last page
/// below the end of the lower half is not used, as in Linux.
pub(crate) const USER_END: usize = 0x0000_7fff_ffff_f000;

/// The top level table that CR3 of each CPU has now. Each CPU changes only its own value, with
/// the big kernel lock or before it runs tasks.
static ACTIVE: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];

fn active() -> &'static AtomicU64 {
    &ACTIVE[cpu::id()]
}

/// The top level table that CR3 of the CPU `id` has now.
pub(crate) fn active_on(id: usize) -> u64 {
    ACTIVE[id].load(Ordering::Acquire)
}

/// Makes the top level table of a new user address space and gives its physical address. The
/// user half is empty, and the kernel half has the entries of the kernel table.
pub(crate) fn new_user_root() -> Option<u64> {
    let root = alloc_table_frame()?;
    copy_kernel_half(root);
    Some(root)
}

/// Gives back the tables of the user half of `root` and `root` itself. The caller removed the
/// mappings of the pages, and `root` is not active on this CPU. Each other CPU that still has
/// `root` loads the kernel table first.
pub(crate) fn free_user_root(root: u64) {
    assert!(active().load(Ordering::Acquire) != root, "the address space is active");
    super::smp::shootdown(root, super::smp::LEAVE);
    fn free_level(table: u64, level: usize) {
        if level > 1 {
            for i in 0..512 {
                let e = read_entry(table, i);
                // A huge page is a frame of user memory, not a table.
                if e & PRESENT != 0 && e & HUGE == 0 {
                    free_level(e & ADDR_MASK, level - 1);
                }
            }
        }
        free_frame_phys(table);
    }
    for i in 0..KERNEL_HALF.start {
        let e = read_entry(root, i);
        if e & PRESENT != 0 {
            free_level(e & ADDR_MASK, 3);
        }
    }
    free_frame_phys(root);
}

/// The page table entry flags for a user page. A page that allows no access is not present, so
/// each access to it is a page fault.
fn user_flags(readable: bool, writable: bool, executable: bool) -> u64 {
    if !(readable || writable || executable) {
        return 0;
    }
    USER | PRESENT | if writable { WRITABLE } else { 0 } | if executable { 0 } else { NO_EXECUTE }
}

/// Gives the last level entry for `virt` in `root`, if the tables to it exist.
fn user_leaf(root: u64, virt: usize) -> Option<(u64, usize)> {
    let [i4, i3, i2, i1] = indexes(virt);
    let mut table = root;
    for i in [i4, i3, i2] {
        let e = read_entry(table, i);
        if e & PRESENT == 0 || e & HUGE != 0 {
            return None;
        }
        table = e & ADDR_MASK;
    }
    Some((table, i1))
}

/// Drops the TLB entry of `virt` on each CPU where `root` is active.
fn flush_user(root: u64, virt: usize) {
    if active().load(Ordering::Acquire) == root {
        flush(virt);
    }
    super::smp::shootdown(root, virt as u64);
}

/// Drops all the TLB entries of user pages on each CPU where `root` is active.
fn flush_user_block(root: u64) {
    if active().load(Ordering::Acquire) == root {
        flush_user_all();
    }
    super::smp::shootdown(root, super::smp::FLUSH_ALL);
}

/// Drops the TLB entries of the huge page at `virt` on each CPU where `root` is active, after the
/// huge page goes away. One `invlpg` drops the entry of the whole huge page on a CPU and on KVM.
/// QEMU without KVM then can keep the code that it translated from the other 4 KiB pages of the
/// huge page, and run the old code at an address that has no page now. Thus all the entries of
/// user pages go there.
fn flush_user_huge(root: u64, virt: usize) {
    if super::under_tcg() {
        flush_user_block(root);
    } else {
        flush_user(root, virt);
    }
}

/// The permissions of a user page: readable, writable and executable.
pub(crate) type UserProt = (bool, bool, bool);

/// Maps one 4 KiB page at `virt` in the user address space `root`. Gives `Err` if no frame is free
/// for a page table. The caller makes sure that `virt` is page aligned, below `USER_END` and not
/// mapped.
pub(crate) fn user_map(root: u64, virt: usize, phys: u64, prot: UserProt) -> Result<(), ()> {
    assert!(virt < USER_END, "{virt:#x} is not in the user half");
    let pt = leaf_table(root, virt, USER)?;
    write_entry(pt, indexes(virt)[3], phys | user_flags(prot.0, prot.1, prot.2));
    flush_user(root, virt);
    Ok(())
}

/// Removes the mapping of one 4 KiB page at `virt` in `root`.
pub(crate) fn user_unmap(root: u64, virt: usize) {
    if let Some((table, i)) = user_leaf(root, virt) {
        write_entry(table, i, 0);
        flush_user(root, virt);
    }
}

/// Changes the permissions of the page at `virt` in `root`, which maps `phys`.
pub(crate) fn user_protect(root: u64, virt: usize, phys: u64, prot: UserProt) {
    if let Some((table, i)) = user_leaf(root, virt) {
        write_entry(table, i, phys | user_flags(prot.0, prot.1, prot.2));
        flush_user(root, virt);
    }
}

/// Maps 4 KiB pages in `root` as `user_map` does, but with no TLB flush. `pages` gives the
/// address, the frame and the permissions of each page, in address order. `root` is a new
/// address space that no CPU has loaded, as the child of `fork`. One walk finds the last level
/// table for all the pages in it. Gives `Err` if no frame is free for a page table.
pub(crate) fn user_map_new(
    root: u64,
    pages: impl Iterator<Item = (usize, u64, UserProt)>,
) -> Result<(), ()> {
    debug_assert!(active().load(Ordering::Acquire) != root, "the address space is active");
    let mut leaf = (usize::MAX, 0);
    for (virt, phys, prot) in pages {
        assert!(virt < USER_END, "{virt:#x} is not in the user half");
        let block = virt & !(HUGE_SIZE as usize - 1);
        if leaf.0 != block {
            leaf = (block, leaf_table(root, virt, USER)?);
        }
        write_entry(leaf.1, indexes(virt)[3], phys | user_flags(prot.0, prot.1, prot.2));
    }
    Ok(())
}

/// Changes the permissions of 4 KiB pages in `root` as `user_protect` does. `pages` gives the
/// address, the frame and the new permissions of each page, in address order. One walk finds the
/// last level table for all the pages in it, and one TLB flush at the end is for all the pages.
pub(crate) fn user_protect_many(root: u64, pages: impl Iterator<Item = (usize, u64, UserProt)>) {
    let mut leaf = (usize::MAX, None);
    let mut changed = false;
    for (virt, phys, prot) in pages {
        let block = virt & !(HUGE_SIZE as usize - 1);
        if leaf.0 != block {
            leaf = (block, user_leaf(root, virt).map(|(table, _)| table));
        }
        if let Some(table) = leaf.1 {
            write_entry(table, indexes(virt)[3], phys | user_flags(prot.0, prot.1, prot.2));
            changed = true;
        }
    }
    if changed {
        flush_user_block(root);
    }
}

/// Maps the 2 MiB page at `phys` at `virt` in `root` with one huge entry. Gives the physical
/// address of a last level table that `user_split_huge` and `user_unmap_huge` use later. If the
/// range has a last level table already, it is that table, else it is a new one. Gives `Err` if no
/// frame is free for a table. The caller makes sure that `virt` and `phys` are 2 MiB aligned and
/// that no 4 KiB page is mapped in the range.
pub(crate) fn user_map_huge(root: u64, virt: usize, phys: u64, prot: UserProt) -> Result<u64, ()> {
    assert!(virt + HUGE_SIZE as usize <= USER_END, "{virt:#x} is not in the user half");
    let [i4, i3, i2, _] = indexes(virt);
    let pdpt = next_table(root, i4, USER)?;
    let pd = next_table(pdpt, i3, USER)?;
    let e = read_entry(pd, i2);
    let table = if e & PRESENT != 0 {
        assert!(e & HUGE == 0, "a huge page is mapped at {virt:#x} already");
        e & ADDR_MASK
    } else {
        alloc_table_frame().ok_or(())?
    };
    let flags = user_flags(prot.0, prot.1, prot.2);
    assert!(flags & PRESENT != 0, "a huge page must allow an access");
    write_entry(pd, i2, phys | flags | HUGE);
    flush_user(root, virt);
    Ok(table)
}

/// Gives the huge entry for `virt` in `root`, as the table, the index and the value.
fn user_huge_entry(root: u64, virt: usize) -> (u64, usize, u64) {
    let [i4, i3, i2, _] = indexes(virt);
    let mut table = root;
    for i in [i4, i3] {
        let e = read_entry(table, i);
        assert!(e & PRESENT != 0, "no huge page is mapped at {virt:#x}");
        table = e & ADDR_MASK;
    }
    let e = read_entry(table, i2);
    assert!(e & PRESENT != 0 && e & HUGE != 0, "no huge page is mapped at {virt:#x}");
    (table, i2, e)
}

/// Changes the permissions of the huge page at `virt` in `root`, which maps the 2 MiB at `phys`.
/// The page stays one huge entry.
pub(crate) fn user_protect_huge(root: u64, virt: usize, phys: u64, prot: UserProt) {
    let (pd, i2, _) = user_huge_entry(root, virt);
    let flags = user_flags(prot.0, prot.1, prot.2);
    assert!(flags & PRESENT != 0, "a huge page must allow an access");
    write_entry(pd, i2, phys | flags | HUGE);
    flush_user(root, virt);
}

/// Changes the huge page at `virt` in `root` to 512 pages of 4 KiB with the same frames and
/// permissions. `table` is the table that `user_map_huge` gave.
pub(crate) fn user_split_huge(root: u64, virt: usize, table: u64) {
    let (pd, i2, e) = user_huge_entry(root, virt);
    let phys = e & ADDR_MASK;
    let flags = e & !ADDR_MASK & !HUGE;
    for i in 0..512 {
        write_entry(table, i, (phys + (i * PAGE_SIZE) as u64) | flags);
    }
    write_entry(pd, i2, table | PRESENT | WRITABLE | USER);
    flush_user(root, virt);
}

/// Removes the huge page at `virt` in `root`. `table` is the table that `user_map_huge` gave. It
/// becomes an empty last level table of `root`, so `free_user_root` frees it.
pub(crate) fn user_unmap_huge(root: u64, virt: usize, table: u64) {
    let (pd, i2, _) = user_huge_entry(root, virt);
    for i in 0..512 {
        write_entry(table, i, 0);
    }
    write_entry(pd, i2, table | PRESENT | WRITABLE | USER);
    flush_user_huge(root, virt);
}

/// Loads `root` into CR3. A value of 0 loads the kernel table.
pub(crate) fn activate(root: u64) {
    let root = if root == 0 { KERNEL_PML4.load(Ordering::Acquire) } else { root };
    if active().swap(root, Ordering::AcqRel) == root {
        return;
    }
    // SAFETY: `root` is the kernel table or a table from `new_user_root`. Each one has the kernel
    // half of the kernel table, so the code, the stack and the data of the kernel stay mapped at
    // the same addresses.
    unsafe { core::arch::asm!("mov cr3, {}", in(reg) root, options(nostack, preserves_flags)) };
}

/// Tells if `root` is in CR3 of this CPU now.
pub(crate) fn is_active(root: u64) -> bool {
    active().load(Ordering::Acquire) == root
}

/// Loads the kernel table if `root` is in CR3 of this CPU, because `root` goes away.
pub(crate) fn leave(root: u64) {
    if is_active(root) {
        activate(0);
    }
}
