//! The kernel page tables of arm64.
//!
//! The kernel uses 4 KiB pages and 48 bit virtual addresses, so a walk has four levels. TTBR1
//! holds the kernel half of the address space. TTBR0 holds the identity map of the boot path only,
//! and the boot path turns its walks off. User space gets TTBR0 later. The kernel half is:
//!
//! - `PAGE_OFFSET`: the direct map of all RAM, as the linear map of Linux.
//! - `MMIO_BASE`: the first 1 GiB of physical addresses as device memory. The boot path maps it
//!   for the UART, the GIC and the RTC of QEMU virt.
//! - `VMALLOC_START` to `HEAP_START`: the vmalloc range, for `vmap`.
//! - `HEAP_START` to `HEAP_END`: the large objects of the kernel heap.
//! - `KERNEL_BASE`: the kernel image, with 4 KiB pages and the permissions of each section.
//!
//! The boot assembly makes the first tables, in boot.rs. `init` puts the direct map of all RAM in
//! place of the small direct map of the boot path.
//!
//! TTBR0 holds the user half. Each user address space has its own top level table. With no user
//! address space, TTBR0 has an empty table, as `reserved_pg_dir` of Linux. The user pages are not
//! global and all address spaces use ASID 0, so a CPU drops the user entries of its TLB when it
//! loads another table.

use super::cpu::{self, MAX_CPUS};
use crate::addr::PAGE_SIZE;
use crate::boot::BootInfo;
use crate::mm::PageInfo;
use crate::mm::frame::{alloc_table_frame, free_frame_phys};
use crate::sync::SpinLock;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// The start of the direct map. Physical address 0 is here.
pub(crate) const PAGE_OFFSET: usize = 0xffff_0000_0000_0000;
/// The start of the device memory window that the boot path maps. Physical address 0 is here.
pub(crate) const MMIO_BASE: usize = 0xffff_0080_0000_0000;
/// The vmalloc range: `vmap` takes addresses from here.
pub(crate) const VMALLOC_START: usize = 0xffff_8000_0000_0000;
/// The range of the large objects of the kernel heap, 4 TiB at the end of the vmalloc range.
pub(crate) const HEAP_START: usize = 0xffff_a000_0000_0000;
/// The end of the heap range and of the vmalloc range.
pub(crate) const HEAP_END: usize = 0xffff_a400_0000_0000;
/// The virtual address of the start of the kernel image. The linker script has the same value.
pub(crate) const KERNEL_BASE: usize = 0xffff_ff80_0000_0000;

/// The direct map covers physical memory below this address: one L0 entry.
const DIRECT_MAP_SIZE: u64 = 1 << 39;

/// The bits of a descriptor, per the Arm ARM section D8.3.
const VALID: u64 = 1 << 0;
/// A table descriptor at levels 0 to 2, or a page descriptor at level 3. A block descriptor at
/// levels 1 and 2 does not have this bit.
const TABLE: u64 = 1 << 1;
/// Index 1 of MAIR_EL1: device memory.
const ATTR_DEVICE: u64 = 1 << 2;
/// The page is not global: its TLB entries belong to one ASID.
const NG: u64 = 1 << 11;
/// EL0 can use the page.
const AP_USER: u64 = 1 << 6;
/// The page is read only.
const AP_RO: u64 = 1 << 7;
const SH_INNER: u64 = 3 << 8;
/// The access flag. The kernel sets it, so the CPU does not fault on the first access.
const AF: u64 = 1 << 10;
/// EL1 cannot execute the page.
const PXN: u64 = 1 << 53;
/// EL0 cannot execute the page.
const UXN: u64 = 1 << 54;
const ADDR_MASK: u64 = 0x0000_ffff_ffff_f000;

/// A page of the kernel text: read only and executable.
pub(crate) const PTE_KERNEL_RX: u64 = VALID | TABLE | AF | SH_INNER | AP_RO | UXN;
/// A page of the kernel rodata.
pub(crate) const PTE_KERNEL_RO: u64 = VALID | TABLE | AF | SH_INNER | AP_RO | PXN | UXN;
/// A page of the kernel data and bss.
pub(crate) const PTE_KERNEL_RW: u64 = VALID | TABLE | AF | SH_INNER | PXN | UXN;
/// A 1 GiB block of the boot direct map.
pub(crate) const BLOCK_DIRECT: u64 = VALID | AF | SH_INNER | PXN | UXN;
/// A 1 GiB block of device memory.
pub(crate) const BLOCK_DEVICE: u64 = VALID | AF | ATTR_DEVICE | PXN | UXN;
/// A 1 GiB block of the boot identity map. The CPU runs the code that turns the MMU on here.
pub(crate) const BLOCK_IDENTITY: u64 = VALID | AF | SH_INNER | UXN;

/// MAIR_EL1: index 0 is normal memory, write back and write allocate. Index 1 is device memory,
/// nGnRE.
pub(crate) const MAIR: u64 = 0x04ff;
/// TCR_EL1 without the IPS field: 48 bit addresses for TTBR0 and TTBR1, 4 KiB pages, and table
/// walks in inner shareable write back memory. The boot path copies IPS from the CPU.
pub(crate) const TCR: u64 = 16
    | (1 << 8)
    | (1 << 10)
    | (3 << 12)
    | (16 << 16)
    | (1 << 24)
    | (1 << 26)
    | (3 << 28)
    | (2 << 30);
/// TCR_EL1.EPD0: no walks of TTBR0.
pub(crate) const TCR_EPD0: u64 = 1 << 7;
/// SCTLR_EL1 with the MMU and the caches off: the bits that are RES1 in Armv8.0.
pub(crate) const SCTLR_MMU_OFF: u64 = 0x30d0_0800;
/// SCTLR_EL1 with the MMU, the caches and the stack alignment check on.
pub(crate) const SCTLR_MMU_ON: u64 = SCTLR_MMU_OFF | (1 << 0) | (1 << 2) | (1 << 3) | (1 << 12);

unsafe extern "C" {
    static rk_boot_k_l0: u8;
    static __text_start: u8;
    static __kernel_end: u8;
}

fn sym(s: *const u8) -> usize {
    s as usize
}

/// The physical address of the start of the kernel image. The boot path sets it.
static KERNEL_PHYS: AtomicU64 = AtomicU64::new(0);

/// Keeps the physical address where the boot loader put the kernel image.
pub(crate) fn set_kernel_phys(phys: u64) {
    KERNEL_PHYS.store(phys, Ordering::Relaxed);
}

/// The physical address range of the kernel image, with the bss and the boot page tables.
pub(crate) fn kernel_phys() -> core::ops::Range<u64> {
    let start = KERNEL_PHYS.load(Ordering::Relaxed);
    start..start + (sym(&raw const __kernel_end) - KERNEL_BASE) as u64
}

/// The virtual address range of the kernel image.
pub(crate) fn kernel_image() -> (usize, usize) {
    (sym(&raw const __text_start), sym(&raw const __kernel_end))
}

/// The physical address of a static in the kernel image.
fn image_phys(virt: usize) -> u64 {
    (virt - KERNEL_BASE) as u64 + KERNEL_PHYS.load(Ordering::Relaxed)
}

/// The physical address of an address in the kernel image, for the start address of a CPU.
pub(crate) fn kernel_virt_to_phys(virt: usize) -> u64 {
    image_phys(virt)
}

/// The virtual address of a physical address in the direct map.
pub(crate) fn phys_to_virt(phys: u64) -> usize {
    PAGE_OFFSET + phys as usize
}

/// The physical address of the top level table of the kernel half.
fn root() -> u64 {
    image_phys(sym(&raw const rk_boot_k_l0))
}

/// One entry of a page table, through the direct map.
fn entry(table: u64, index: usize) -> &'static AtomicU64 {
    debug_assert!(index < 512);
    // SAFETY: each table is a frame that the page table code owns. It is in RAM, so the direct map
    // maps it, and it lives as long as the kernel. The CPU reads the entries, and the code writes
    // them with atomic stores, so a reference to an atomic value is sound.
    unsafe { &*(phys_to_virt(table) as *const AtomicU64).wrapping_add(index) }
}

/// The table indexes of a virtual address, from level 0 to level 3.
fn indexes(virt: usize) -> [usize; 4] {
    [(virt >> 39) & 511, (virt >> 30) & 511, (virt >> 21) & 511, (virt >> 12) & 511]
}

/// Makes the writes to the page tables visible to the table walker of each CPU.
fn sync_tables() {
    // SAFETY: the barriers change no memory and no register.
    unsafe { core::arch::asm!("dsb ishst", "isb", options(nostack, preserves_flags)) };
}

/// Removes the TLB entries of one page of the kernel half on all CPUs.
fn flush(virt: usize) {
    let arg = (virt >> 12) & ((1 << 44) - 1);
    // SAFETY: the TLB invalidation and the barriers change no memory.
    unsafe {
        core::arch::asm!(
            "dsb ishst",
            "tlbi vaae1is, {}",
            "dsb ish",
            "isb",
            in(reg) arg,
            options(nostack, preserves_flags),
        );
    }
}

/// Gives the entry at `level` for `virt`, in the subtree of the table `table` at `start` level.
/// A missing table comes from `alloc` when `alloc` gives one. A block on the way gives `None`.
fn walk(
    mut table: u64,
    start: usize,
    level: usize,
    virt: usize,
    alloc: &mut dyn FnMut() -> Option<u64>,
) -> Option<&'static AtomicU64> {
    let index = indexes(virt);
    for &i in &index[start..level] {
        let e = entry(table, i);
        let value = e.load(Ordering::Relaxed);
        table = if value & VALID == 0 {
            let new = alloc()?;
            // The zeros of the new table must be visible before the walker can see the table.
            sync_tables();
            // Two CPUs can make the same table of a user address space at the same time, when
            // they hold the locks of two blocks under it (`VmSpace`). The first one puts its table
            // in the entry, and the other gives its table back, as `pmd_install` of Linux
            // (mm/memory.c). The kernel tables change under `TABLES`, so the swap does not fail
            // for them, and a table of `pool_alloc` is never given back.
            match e.compare_exchange(
                value,
                new | VALID | TABLE,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => new,
                Err(other) => {
                    free_frame_phys(new);
                    if other & TABLE == 0 {
                        return None;
                    }
                    other & ADDR_MASK
                }
            }
        } else if value & TABLE == 0 {
            return None;
        } else {
            value & ADDR_MASK
        };
    }
    Some(entry(table, index[level]))
}

/// Serializes the changes to the kernel page tables.
static TABLES: SpinLock<()> = SpinLock::new(());

/// The page tables of the direct map that `init` makes. They come from the kernel image, because
/// the frame allocator gives frames that the boot direct map can miss.
#[repr(C, align(4096))]
struct PoolTable([AtomicU64; 512]);

const POOL_TABLES: usize = 16;
static POOL: [PoolTable; POOL_TABLES] =
    [const { PoolTable([const { AtomicU64::new(0) }; 512]) }; POOL_TABLES];
static POOL_USED: AtomicUsize = AtomicUsize::new(0);

fn pool_alloc() -> Option<u64> {
    let i = POOL_USED.fetch_add(1, Ordering::Relaxed);
    POOL.get(i).map(|t| image_phys(core::ptr::from_ref(t) as usize))
}

/// Maps the physical range `start..end` in the direct map subtree `l1`, with the largest blocks
/// that fit.
fn map_direct(l1: u64, start: u64, end: u64) {
    const GIB: u64 = 1 << 30;
    const MIB2: u64 = 2 << 20;
    const PAGE: u64 = 4096;
    let mut a = start.next_multiple_of(PAGE);
    let end = (end & !(PAGE - 1)).min(DIRECT_MAP_SIZE);
    while a < end {
        let (level, size) = if a.is_multiple_of(GIB) && end - a >= GIB {
            (1, GIB)
        } else if a.is_multiple_of(MIB2) && end - a >= MIB2 {
            (2, MIB2)
        } else {
            (3, PAGE)
        };
        let virt = PAGE_OFFSET + a as usize;
        let Some(e) = walk(l1, 1, level, virt, &mut pool_alloc) else {
            panic!("no page table for the direct map at {a:#x}");
        };
        let kind = if level == 3 { TABLE } else { 0 };
        e.store(a | BLOCK_DIRECT | kind, Ordering::Relaxed);
        a += size;
    }
}

/// Puts the direct map of all RAM in place of the boot direct map. The boot CPU calls this one
/// time, after `frame::init` and before the heap is used.
pub(crate) fn init(info: &BootInfo) {
    let _guard = TABLES.lock();
    let Some(l1) = pool_alloc() else { unreachable!("the pool has tables") };
    for r in info.memory() {
        let start = r.start.get();
        let end = start.saturating_add(r.len);
        if end > DIRECT_MAP_SIZE {
            crate::println!("paging: memory above 512 GiB is not in the direct map");
        }
        map_direct(l1, start, end);
    }
    // SAFETY: the boot assembly made this table. It is in the kernel image, so the kernel mapping
    // reaches it while the direct map is changed.
    let l0 = unsafe { &*(&raw const rk_boot_k_l0).cast::<AtomicU64>() };
    // The entry changes from one table to another, so it goes through an invalid entry, per the
    // Arm ARM section D8.16.1. No code uses the direct map in this time.
    l0.store(0, Ordering::Relaxed);
    // SAFETY: the TLB invalidation and the barriers change no memory.
    unsafe {
        core::arch::asm!(
            "dsb ishst",
            "tlbi vmalle1is",
            "dsb ish",
            "isb",
            options(nostack, preserves_flags)
        );
    }
    l0.store(l1 | VALID | TABLE, Ordering::Relaxed);
    sync_tables();
}

/// The size of the device window that the boot path maps at `MMIO_BASE`.
const BOOT_MMIO_SIZE: u64 = 1 << 30;

/// Maps the device registers at the physical range `phys..phys + len` as device memory in the
/// window at `MMIO_BASE`, and gives the virtual address of `phys`. The boot path maps the first
/// 1 GiB. Other ranges get 2 MiB blocks. A range at or above 512 GiB, or a block that holds RAM,
/// gives `None`. The boot CPU calls this after `frame::init` and `init`.
pub(crate) fn map_device(phys: u64, len: u64, info: &BootInfo) -> Option<usize> {
    const MIB2: u64 = 2 << 20;
    let end = phys.checked_add(len.max(1))?;
    if end > DIRECT_MAP_SIZE {
        return None;
    }
    if end <= BOOT_MMIO_SIZE {
        return Some(MMIO_BASE + phys as usize);
    }
    let start = (phys & !(MIB2 - 1)).max(BOOT_MMIO_SIZE);
    let end = end.next_multiple_of(MIB2);
    // A device block must not hold RAM: the two mappings would have attributes that differ.
    let ram = info.memory().iter().any(|r| r.start.get() < end && start < r.start.get() + r.len);
    if ram {
        return None;
    }
    let _guard = TABLES.lock();
    let mut a = start;
    while a < end {
        let virt = MMIO_BASE + a as usize;
        let e = walk(root(), 0, 2, virt, &mut alloc_table_frame)?;
        if e.load(Ordering::Relaxed) & VALID == 0 {
            e.store(a | BLOCK_DEVICE, Ordering::Relaxed);
        }
        a += MIB2;
    }
    sync_tables();
    Some(MMIO_BASE + phys as usize)
}

/// Maps one 4 KiB page of the vmalloc range.
pub(crate) fn map_page(virt: usize, phys: u64, writable: bool) -> Result<(), ()> {
    assert!((VMALLOC_START..HEAP_END).contains(&virt), "{virt:#x} is not in the vmalloc range");
    let _guard = TABLES.lock();
    let e = walk(root(), 0, 3, virt, &mut alloc_table_frame).ok_or(())?;
    if e.load(Ordering::Relaxed) & VALID != 0 {
        return Err(());
    }
    let ro = if writable { 0 } else { AP_RO };
    e.store(phys | VALID | TABLE | AF | SH_INNER | PXN | UXN | ro, Ordering::Relaxed);
    sync_tables();
    Ok(())
}

/// Removes the mapping of one 4 KiB page of the vmalloc range. Gives the physical address that
/// it mapped.
pub(crate) fn unmap_page(virt: usize) -> Option<u64> {
    assert!((VMALLOC_START..HEAP_END).contains(&virt), "{virt:#x} is not in the vmalloc range");
    let _guard = TABLES.lock();
    let e = walk(root(), 0, 3, virt, &mut || None)?;
    let value = e.load(Ordering::Relaxed);
    if value & VALID == 0 {
        return None;
    }
    e.store(0, Ordering::Relaxed);
    flush(virt);
    Some(value & ADDR_MASK)
}

/// Removes the mappings of `pages` 4 KiB pages of the heap range from `virt`, with one barrier for
/// the range, as `flush_tlb_kernel_range` of Linux. Then `free` gets the physical address of each
/// page that was mapped. The TLB invalidations go to each CPU, so no interrupt is needed. The heap
/// does not use an address again, so no map comes between the two steps.
pub(crate) fn unmap_pages(virt: usize, pages: usize, free: &mut dyn FnMut(u64)) {
    if pages == 0 {
        return;
    }
    let end = virt + pages * PAGE_SIZE;
    assert!(HEAP_START <= virt && end <= HEAP_END, "{virt:#x} is not in the heap range");
    let _guard = TABLES.lock();
    // First the entries lose their valid bit and keep the address, so that each CPU stops the use
    // of the pages before the frames go back.
    for at in (virt..end).step_by(PAGE_SIZE) {
        if let Some(e) = walk(root(), 0, 3, at, &mut || None) {
            let value = e.load(Ordering::Relaxed);
            if value & VALID != 0 {
                e.store(value & !VALID, Ordering::Relaxed);
            }
        }
    }
    // SAFETY: the TLB invalidations and the barriers change no memory.
    unsafe { core::arch::asm!("dsb ishst", options(nostack, preserves_flags)) };
    for at in (virt..end).step_by(PAGE_SIZE) {
        let arg = (at >> 12) & ((1 << 44) - 1);
        // SAFETY: as above.
        unsafe {
            core::arch::asm!("tlbi vaae1is, {}", in(reg) arg, options(nostack, preserves_flags));
        }
    }
    // SAFETY: as above.
    unsafe { core::arch::asm!("dsb ish", "isb", options(nostack, preserves_flags)) };
    for at in (virt..end).step_by(PAGE_SIZE) {
        if let Some(e) = walk(root(), 0, 3, at, &mut || None) {
            let value = e.swap(0, Ordering::Relaxed);
            if value != 0 {
                free(value & ADDR_MASK);
            }
        }
    }
}

/// Walks the kernel page tables for one virtual address.
pub(crate) fn query(virt: usize) -> Option<PageInfo> {
    // The kernel tables do not map the lower half. User address spaces map it in TTBR0.
    if virt < PAGE_OFFSET {
        return None;
    }
    let mut table = root();
    for (level, i) in indexes(virt).into_iter().enumerate() {
        let e = entry(table, i).load(Ordering::Relaxed);
        if e & VALID == 0 {
            return None;
        }
        let size = match level {
            1 | 2 if e & TABLE == 0 => 1u64 << (39 - 9 * level),
            3 => 4096,
            _ => {
                table = e & ADDR_MASK;
                continue;
            }
        };
        let phys = (e & ADDR_MASK & !(size - 1)) + (virt as u64 & (size - 1));
        return Some(PageInfo {
            phys: crate::addr::PhysAddr::new(phys),
            writable: e & AP_RO == 0,
            executable: e & PXN == 0,
            user: e & AP_USER != 0,
        });
    }
    None
}

/// The end of the user half of the address space. Linux names it `TASK_SIZE`. TTBR0 maps 48 bits.
/// The last page below the end is not used, as on x86-64.
pub(crate) const USER_END: usize = 0x0000_ffff_ffff_f000;

/// The empty top level table that TTBR0 has when no user address space is active.
#[repr(C, align(4096))]
struct EmptyTable([u64; 512]);

static EMPTY: EmptyTable = EmptyTable([0; 512]);

/// The physical address of the empty table.
fn empty_root() -> u64 {
    image_phys(core::ptr::from_ref(&EMPTY) as usize)
}

/// The user table that TTBR0 of each CPU has now, or 0 for the empty table. Each CPU changes
/// only its own value.
static ACTIVE: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];

fn active() -> &'static AtomicU64 {
    &ACTIVE[cpu::id()]
}

/// The user table that TTBR0 of the CPU `id` has now, or 0.
pub(crate) fn active_on(id: usize) -> u64 {
    ACTIVE[id].load(Ordering::Acquire)
}

/// Loads `root` in TTBR0 and drops the user entries of the TLB of this CPU.
fn load_ttbr0(root: u64) {
    // SAFETY: `root` is the empty table or a table from `new_user_root`, which maps only user
    // pages. The kernel runs from TTBR1, so its code, stack and data stay mapped. The TLB
    // invalidation drops the entries of ASID 0, which are the entries of the old table.
    unsafe {
        core::arch::asm!(
            "msr ttbr0_el1, {root}",
            "isb",
            "tlbi aside1, xzr",
            "dsb nsh",
            "isb",
            root = in(reg) root,
            options(nostack, preserves_flags),
        );
    }
}

/// Turns on the walks of TTBR0 with the empty table. Each CPU calls this one time, after the boot
/// path turned the walks off.
pub(crate) fn init_cpu() {
    load_ttbr0(empty_root());
    // SAFETY: TTBR0 has the empty table, so the walks find no mapping. The change of TCR_EL1 does
    // not change the kernel half.
    unsafe {
        core::arch::asm!(
            "mrs {t}, tcr_el1",
            "bic {t}, {t}, #{epd0}",
            "msr tcr_el1, {t}",
            "isb",
            t = out(reg) _,
            epd0 = const TCR_EPD0,
            options(nostack, preserves_flags),
        );
    }
    active().store(0, Ordering::Release);
}

/// Makes the top level table of a new user address space and gives its physical address.
pub(crate) fn new_user_root() -> Option<u64> {
    alloc_table_frame()
}

/// Gives back the tables of `root` and `root` itself. The caller removed the mappings of the
/// pages, and `root` is not active on this CPU. Each other CPU that still has `root` loads the
/// empty table first.
pub(crate) fn free_user_root(root: u64) {
    assert!(active().load(Ordering::Acquire) != root, "the address space is active");
    super::smp::shootdown(root, super::smp::LEAVE);
    fn free_level(table: u64, level: usize) {
        if level < 3 {
            for i in 0..512 {
                let e = entry(table, i).load(Ordering::Relaxed);
                if e & VALID != 0 && e & TABLE != 0 {
                    free_level(e & ADDR_MASK, level + 1);
                }
            }
        }
        free_frame_phys(table);
    }
    free_level(root, 0);
}

/// The descriptor bits of a user page. A page that allows no access is not valid, so each access
/// to it is a fault. EL0 cannot have a page that it can write but not read, so a writable page is
/// readable too. EL1 never executes a user page.
fn user_flags(readable: bool, writable: bool, executable: bool) -> u64 {
    if !(readable || writable || executable) {
        return 0;
    }
    VALID
        | TABLE
        | AF
        | SH_INNER
        | NG
        | AP_USER
        | PXN
        | if writable { 0 } else { AP_RO }
        | if executable { 0 } else { UXN }
}

/// Drops the TLB entries of the user page `virt` on each CPU. The TLB invalidation goes to each
/// CPU of the inner shareable domain, so no interrupt is needed.
fn flush_user(virt: usize) {
    let arg = (virt >> 12) & ((1 << 44) - 1);
    // SAFETY: the TLB invalidation and the barriers change no memory. The ASID field is 0.
    unsafe {
        core::arch::asm!(
            "dsb ishst",
            "tlbi vae1is, {}",
            "dsb ish",
            "isb",
            in(reg) arg,
            options(nostack, preserves_flags),
        );
    }
}

/// The permissions of a user page: readable, writable and executable.
pub(crate) type UserProt = (bool, bool, bool);

/// Maps one 4 KiB page at `virt` in the user address space `root`. Gives `Err` if no frame is free
/// for a page table. The caller makes sure that `virt` is page aligned, below `USER_END` and not
/// mapped.
pub(crate) fn user_map(root: u64, virt: usize, phys: u64, prot: UserProt) -> Result<(), ()> {
    assert!(virt < USER_END, "{virt:#x} is not in the user half");
    let e = walk(root, 0, 3, virt, &mut alloc_table_frame).ok_or(())?;
    if prot.2 {
        sync_icache(phys);
    }
    e.store(phys | user_flags(prot.0, prot.1, prot.2), Ordering::Relaxed);
    flush_user(virt);
    Ok(())
}

/// Makes the instruction fetches see the data in the frame at `phys`, as `__sync_icache_dcache` of
/// Linux does before it maps an executable page. The kernel writes code through the direct map, and
/// the instruction cache of arm64 is not coherent with the data cache. CTR_EL0.IDC and CTR_EL0.DIC
/// tell that a step is not needed.
fn sync_icache(phys: u64) {
    let ctr: u64;
    // SAFETY: reading CTR_EL0 has no side effect.
    unsafe { core::arch::asm!("mrs {}, ctr_el0", out(reg) ctr, options(nomem, nostack)) };
    let start = phys_to_virt(phys);
    let end = start + 4096;
    if ctr & (1 << 28) == 0 {
        let line = 4 << (ctr >> 16 & 0xf);
        for addr in (start..end).step_by(line) {
            // SAFETY: the clean writes dirty lines of the page to the point of unification. The
            // page is mapped in the direct map, and its data does not change.
            unsafe { core::arch::asm!("dc cvau, {}", in(reg) addr, options(nostack)) };
        }
    }
    // SAFETY: the barrier changes no memory.
    unsafe { core::arch::asm!("dsb ish", options(nostack, preserves_flags)) };
    if ctr & (1 << 29) == 0 {
        let line = 4 << (ctr & 0xf);
        for addr in (start..end).step_by(line) {
            // SAFETY: the invalidation removes lines from the instruction cache only.
            unsafe { core::arch::asm!("ic ivau, {}", in(reg) addr, options(nostack)) };
        }
        // SAFETY: the barrier changes no memory.
        unsafe { core::arch::asm!("dsb ish", "isb", options(nostack, preserves_flags)) };
    }
}

/// Removes the mapping of one 4 KiB page at `virt` in `root`.
pub(crate) fn user_unmap(root: u64, virt: usize) {
    if let Some(e) = walk(root, 0, 3, virt, &mut || None) {
        e.store(0, Ordering::Relaxed);
        flush_user(virt);
    }
}

/// Changes the permissions of the page at `virt` in `root`, which maps `phys`.
pub(crate) fn user_protect(root: u64, virt: usize, phys: u64, prot: UserProt) {
    if let Some(e) = walk(root, 0, 3, virt, &mut || None) {
        if prot.2 {
            sync_icache(phys);
        }
        e.store(phys | user_flags(prot.0, prot.1, prot.2), Ordering::Relaxed);
        flush_user(virt);
    }
}

/// Drops the TLB entries of all the user pages on each CPU. All user pages have ASID 0. The TLB
/// invalidation goes to each CPU of the inner shareable domain, so no interrupt is needed.
fn flush_user_all() {
    // SAFETY: the TLB invalidation and the barriers change no memory.
    unsafe {
        core::arch::asm!(
            "dsb ishst",
            "tlbi aside1is, xzr",
            "dsb ish",
            "isb",
            options(nostack, preserves_flags),
        );
    }
}

/// Maps 4 KiB pages in `root` as `user_map` does, but with no TLB flush. `pages` gives the
/// address, the frame and the permissions of each page, in address order. `root` is a new
/// address space that no CPU has loaded, as the child of `fork`. One walk finds the level 3 table
/// for all the pages in it. Gives `Err` if no frame is free for a page table.
///
/// The instruction cache needs no step: the frames are the frames of the parent, which has them
/// executable already, and `user_map` or `user_protect` made the instruction fetches see them.
pub(crate) fn user_map_new(
    root: u64,
    pages: impl Iterator<Item = (usize, u64, UserProt)>,
) -> Result<(), ()> {
    debug_assert!(active().load(Ordering::Acquire) != root, "the address space is active");
    let mut leaf = (usize::MAX, 0);
    for (virt, phys, prot) in pages {
        assert!(virt < USER_END, "{virt:#x} is not in the user half");
        let block = virt & !(BLOCK_SIZE - 1);
        if leaf.0 != block {
            let e = walk(root, 0, 2, virt, &mut alloc_table_frame).ok_or(())?;
            let value = e.load(Ordering::Relaxed);
            let table = if value & VALID == 0 {
                let new = alloc_table_frame().ok_or(())?;
                sync_tables();
                e.store(new | VALID | TABLE, Ordering::Relaxed);
                new
            } else {
                assert!(value & TABLE != 0, "a huge page is in the path of a 4 KiB mapping");
                value & ADDR_MASK
            };
            leaf = (block, table);
        }
        entry(leaf.1, indexes(virt)[3])
            .store(phys | user_flags(prot.0, prot.1, prot.2), Ordering::Relaxed);
    }
    sync_tables();
    Ok(())
}

/// Changes the permissions of 4 KiB pages in `root` as `user_protect` does, but with no TLB
/// invalidation. `pages` gives the address, the frame and the new permissions of each page, in
/// address order. One walk finds the level 3 table for all the pages in it. Gives `true` if an
/// entry changed. The caller then calls `user_flush_all`, one time for all the pages.
pub(crate) fn user_protect_many(
    root: u64,
    pages: impl Iterator<Item = (usize, u64, UserProt)>,
) -> bool {
    let mut leaf = (usize::MAX, None);
    let mut changed = false;
    for (virt, phys, prot) in pages {
        let block = virt & !(BLOCK_SIZE - 1);
        if leaf.0 != block {
            let e = walk(root, 0, 2, virt, &mut || None).map(|e| e.load(Ordering::Relaxed));
            let table = e.filter(|v| v & VALID != 0 && v & TABLE != 0).map(|v| v & ADDR_MASK);
            leaf = (block, table);
        }
        if let Some(table) = leaf.1 {
            if prot.2 {
                sync_icache(phys);
            }
            entry(table, indexes(virt)[3])
                .store(phys | user_flags(prot.0, prot.1, prot.2), Ordering::Relaxed);
            changed = true;
        }
    }
    changed
}

/// Drops the TLB entries of all the user pages on each CPU, after `user_protect_many`.
pub(crate) fn user_flush_all(_root: u64) {
    flush_user_all();
}

/// The size of a block at level 2.
const BLOCK_SIZE: usize = 2 << 20;

/// Maps the 2 MiB block at `phys` at `virt` in `root` with one level 2 block descriptor. Gives the
/// physical address of a level 3 table that `user_split_huge` and `user_unmap_huge` use later. If
/// the range has a level 3 table already, it is that table, else it is a new one. Gives `Err` if
/// no frame is free for a table. The caller makes sure that `virt` and `phys` are 2 MiB aligned
/// and that no 4 KiB page is mapped in the range.
pub(crate) fn user_map_huge(root: u64, virt: usize, phys: u64, prot: UserProt) -> Result<u64, ()> {
    assert!(virt + BLOCK_SIZE <= USER_END, "{virt:#x} is not in the user half");
    let e = walk(root, 0, 2, virt, &mut alloc_table_frame).ok_or(())?;
    let old = e.load(Ordering::Relaxed);
    let table = if old & VALID != 0 {
        assert!(old & TABLE != 0, "a huge page is mapped at {virt:#x} already");
        old & ADDR_MASK
    } else {
        alloc_table_frame().ok_or(())?
    };
    let flags = user_flags(prot.0, prot.1, prot.2);
    assert!(flags & VALID != 0, "a huge page must allow an access");
    if prot.2 {
        for i in 0..BLOCK_SIZE / 4096 {
            sync_icache(phys + (i * 4096) as u64);
        }
    }
    // Break before make: the walker must not see the table and the block at the same time.
    e.store(0, Ordering::Relaxed);
    flush_user(virt);
    e.store(phys | (flags & !TABLE), Ordering::Relaxed);
    flush_user(virt);
    Ok(table)
}

/// Gives the level 2 entry of the block at `virt` in `root`.
fn user_block(root: u64, virt: usize) -> &'static AtomicU64 {
    let e = walk(root, 0, 2, virt, &mut || None);
    let e = e.unwrap_or_else(|| panic!("no huge page is mapped at {virt:#x}"));
    let value = e.load(Ordering::Relaxed);
    assert!(value & VALID != 0 && value & TABLE == 0, "no huge page is mapped at {virt:#x}");
    e
}

/// Changes the permissions of the block at `virt` in `root`, which maps the 2 MiB at `phys`. The
/// block stays one block descriptor.
pub(crate) fn user_protect_huge(root: u64, virt: usize, phys: u64, prot: UserProt) {
    let e = user_block(root, virt);
    let flags = user_flags(prot.0, prot.1, prot.2);
    assert!(flags & VALID != 0, "a huge page must allow an access");
    if prot.2 {
        for i in 0..BLOCK_SIZE / 4096 {
            sync_icache(phys + (i * 4096) as u64);
        }
    }
    // Break before make, as in `user_map_huge`.
    e.store(0, Ordering::Relaxed);
    flush_user(virt);
    e.store(phys | (flags & !TABLE), Ordering::Relaxed);
    flush_user(virt);
}

/// Changes the block at `virt` in `root` to 512 pages of 4 KiB with the same frames and
/// permissions. `table` is the table that `user_map_huge` gave.
pub(crate) fn user_split_huge(root: u64, virt: usize, table: u64) {
    let e = user_block(root, virt);
    let value = e.load(Ordering::Relaxed);
    let phys = value & ADDR_MASK;
    let flags = (value & !ADDR_MASK) | TABLE;
    for i in 0..512 {
        entry(table, i).store((phys + (i * 4096) as u64) | flags, Ordering::Relaxed);
    }
    e.store(0, Ordering::Relaxed);
    flush_user(virt);
    sync_tables();
    e.store(table | VALID | TABLE, Ordering::Relaxed);
    flush_user(virt);
}

/// Removes the block at `virt` in `root`. `table` is the table that `user_map_huge` gave. It
/// becomes an empty level 3 table of `root`, so `free_user_root` frees it.
pub(crate) fn user_unmap_huge(root: u64, virt: usize, table: u64) {
    let e = user_block(root, virt);
    e.store(0, Ordering::Relaxed);
    flush_user(virt);
    for i in 0..512 {
        entry(table, i).store(0, Ordering::Relaxed);
    }
    sync_tables();
    e.store(table | VALID | TABLE, Ordering::Relaxed);
    flush_user(virt);
}

/// Loads `root` in TTBR0. A value of 0 loads the empty table.
pub(crate) fn activate(root: u64) {
    if active().swap(root, Ordering::SeqCst) == root {
        return;
    }
    load_ttbr0(if root == 0 { empty_root() } else { root });
}

/// Tells if `root` is in TTBR0 of this CPU now.
pub(crate) fn is_active(root: u64) -> bool {
    active().load(Ordering::Acquire) == root
}

/// Loads the empty table if `root` is in TTBR0 of this CPU, because `root` goes away.
pub(crate) fn leave(root: u64) {
    if is_active(root) {
        activate(0);
    }
}
