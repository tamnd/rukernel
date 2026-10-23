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

/// The physical address of the end of the kernel image.
pub(crate) fn kernel_end_phys() -> u64 {
    (sym(&raw const __kernel_end) - KERNEL_BASE) as u64
}

/// The virtual address range of the kernel image.
pub(crate) fn kernel_image() -> (usize, usize) {
    (sym(&raw const __text_start), sym(&raw const __kernel_end))
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

fn flush(virt: usize) {
    // SAFETY: invlpg only drops a TLB entry.
    unsafe { core::arch::asm!("invlpg [{}]", in(reg) virt, options(nostack, preserves_flags)) };
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
    for r in core::iter::once(&first_mib).chain(ram) {
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
    ACTIVE.store(pml4, Ordering::Release);
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
    Some(e & ADDR_MASK)
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

/// The top level table that CR3 has now.
static ACTIVE: AtomicU64 = AtomicU64::new(0);

/// Makes the top level table of a new user address space and gives its physical address. The
/// user half is empty, and the kernel half has the entries of the kernel table.
pub(crate) fn new_user_root() -> Option<u64> {
    let root = alloc_table_frame()?;
    let kernel = KERNEL_PML4.load(Ordering::Acquire);
    for i in KERNEL_HALF {
        write_entry(root, i, read_entry(kernel, i));
    }
    Some(root)
}

/// Gives back the tables of the user half of `root` and `root` itself. The caller removed the
/// mappings of the pages, and `root` is not active.
pub(crate) fn free_user_root(root: u64) {
    assert!(ACTIVE.load(Ordering::Acquire) != root, "the address space is active");
    fn free_level(table: u64, level: usize) {
        if level > 1 {
            for i in 0..512 {
                let e = read_entry(table, i);
                if e & PRESENT != 0 {
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

/// The page table entry flags for a user page.
fn user_flags(writable: bool, executable: bool) -> u64 {
    USER | PRESENT | if writable { WRITABLE } else { 0 } | if executable { 0 } else { NO_EXECUTE }
}

/// Gives the last level entry for `virt` in `root`, if the tables to it exist.
fn user_leaf(root: u64, virt: usize) -> Option<(u64, usize)> {
    let [i4, i3, i2, i1] = indexes(virt);
    let mut table = root;
    for i in [i4, i3, i2] {
        let e = read_entry(table, i);
        if e & PRESENT == 0 {
            return None;
        }
        table = e & ADDR_MASK;
    }
    Some((table, i1))
}

/// Drops the TLB entry of `virt` if `root` is active.
fn flush_user(root: u64, virt: usize) {
    if ACTIVE.load(Ordering::Acquire) == root {
        flush(virt);
    }
}

/// Maps one 4 KiB page at `virt` in the user address space `root`. Gives `Err` if no frame is free
/// for a page table. The caller makes sure that `virt` is page aligned, below `USER_END` and not
/// mapped.
pub(crate) fn user_map(
    root: u64,
    virt: usize,
    phys: u64,
    writable: bool,
    executable: bool,
) -> Result<(), ()> {
    assert!(virt < USER_END, "{virt:#x} is not in the user half");
    let pt = leaf_table(root, virt, USER)?;
    write_entry(pt, indexes(virt)[3], phys | user_flags(writable, executable));
    flush_user(root, virt);
    Ok(())
}

/// Removes the mapping of one 4 KiB page at `virt` in `root`, and gives the physical address that
/// it mapped.
pub(crate) fn user_unmap(root: u64, virt: usize) -> Option<u64> {
    let (table, i) = user_leaf(root, virt)?;
    let e = read_entry(table, i);
    if e & PRESENT == 0 {
        return None;
    }
    write_entry(table, i, 0);
    flush_user(root, virt);
    Some(e & ADDR_MASK)
}

/// Changes the permissions of a mapped page at `virt` in `root`.
pub(crate) fn user_protect(root: u64, virt: usize, writable: bool, executable: bool) {
    if let Some((table, i)) = user_leaf(root, virt) {
        let e = read_entry(table, i);
        if e & PRESENT != 0 {
            write_entry(table, i, (e & ADDR_MASK) | user_flags(writable, executable));
            flush_user(root, virt);
        }
    }
}

/// Walks the user address space `root` for one virtual address.
pub(crate) fn user_query(root: u64, virt: usize) -> Option<PageInfo> {
    let (table, i) = user_leaf(root, virt)?;
    let e = read_entry(table, i);
    if e & PRESENT == 0 {
        return None;
    }
    Some(PageInfo {
        phys: crate::addr::PhysAddr::new(e & ADDR_MASK),
        writable: e & WRITABLE != 0,
        executable: e & NO_EXECUTE == 0,
        user: true,
    })
}

/// Loads `root` into CR3. A value of 0 loads the kernel table.
pub(crate) fn activate(root: u64) {
    let root = if root == 0 { KERNEL_PML4.load(Ordering::Acquire) } else { root };
    if ACTIVE.swap(root, Ordering::AcqRel) == root {
        return;
    }
    // SAFETY: `root` is the kernel table or a table from `new_user_root`. Each one has the kernel
    // half of the kernel table, so the code, the stack and the data of the kernel stay mapped at
    // the same addresses.
    unsafe { core::arch::asm!("mov cr3, {}", in(reg) root, options(nostack, preserves_flags)) };
}

/// Tells if `root` is in CR3 now.
pub(crate) fn is_active(root: u64) -> bool {
    ACTIVE.load(Ordering::Acquire) == root
}
