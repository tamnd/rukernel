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

use crate::boot::BootInfo;
use crate::mm::PageInfo;
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
            e.store(new | VALID | TABLE, Ordering::Relaxed);
            new
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

/// Maps one 4 KiB page of the vmalloc range.
pub(crate) fn map_page(virt: usize, phys: u64, writable: bool) -> Result<(), ()> {
    assert!((VMALLOC_START..HEAP_END).contains(&virt), "{virt:#x} is not in the vmalloc range");
    let _guard = TABLES.lock();
    let e = walk(root(), 0, 3, virt, &mut crate::mm::frame::alloc_table_frame).ok_or(())?;
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

/// Walks the kernel page tables for one virtual address.
pub(crate) fn query(virt: usize) -> Option<PageInfo> {
    // The boot path turned off the walks of TTBR0, so the lower half has no mapping.
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
