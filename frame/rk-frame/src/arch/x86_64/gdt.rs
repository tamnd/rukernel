//! The global descriptor table and the task state segment.
//!
//! The selectors are the same as the selectors of Linux. User programs see them: `ptrace` gives
//! `cs` and `ss`, and a signal frame contains them. The SYSCALL and SYSRET instructions also need
//! this order, because SYSRET takes the user selectors from the STAR MSR at fixed offsets.
//!
//! In R0 there is one CPU, so there is one table. The tables become per CPU in R2.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};

/// The 64 bit kernel code segment. Linux names it `__KERNEL_CS`.
pub(crate) const KERNEL_CS: u16 = 0x10;
/// The kernel data segment. Linux names it `__KERNEL_DS`.
pub(crate) const KERNEL_DS: u16 = 0x18;
/// The 32 bit user code segment, for compat programs. Linux names it `__USER32_CS`.
pub(crate) const USER32_CS: u16 = 0x23;
/// The user data segment. Linux names it `__USER_DS`.
pub(crate) const USER_DS: u16 = 0x2b;
/// The 64 bit user code segment. Linux names it `__USER_CS`.
pub(crate) const USER_CS: u16 = 0x33;
/// The task state segment. It uses two slots.
const TSS_SELECTOR: u16 = 0x40;

/// The interrupt stack table slot for a double fault.
pub(crate) const IST_DOUBLE_FAULT: u8 = 1;
/// The interrupt stack table slot for a non maskable interrupt.
pub(crate) const IST_NMI: u8 = 2;
/// The interrupt stack table slot for a machine check.
pub(crate) const IST_MACHINE_CHECK: u8 = 3;

/// The size of each interrupt stack and of the entry stack.
const IST_STACK_SIZE: usize = 16 * 1024;

/// The index of the entry stack in `Tables::stacks`. The CPU loads RSP0 of the TSS when a trap
/// comes from user mode, so the trap entry code runs on this stack.
const ENTRY_STACK: usize = 3;

/// The 64 bit task state segment.
#[repr(C, packed(4))]
struct Tss {
    reserved0: u32,
    rsp: [u64; 3],
    reserved1: u64,
    ist: [u64; 7],
    reserved2: u64,
    reserved3: u16,
    iomap_base: u16,
}

#[repr(C, align(16))]
struct Stack([u8; IST_STACK_SIZE]);

/// The tables of the boot CPU. The CPU writes the busy bit of the TSS descriptor, so the tables
/// are in an `UnsafeCell` and Rust never makes a reference to them after the load.
struct Tables {
    gdt: UnsafeCell<[u64; 10]>,
    tss: UnsafeCell<Tss>,
    stacks: UnsafeCell<[Stack; 4]>,
}

// SAFETY: only `init` writes the tables, one time, before the CPU loads them. The `LOADED` flag
// makes sure of this.
unsafe impl Sync for Tables {}

static TABLES: Tables = Tables {
    gdt: UnsafeCell::new([0; 10]),
    tss: UnsafeCell::new(Tss {
        reserved0: 0,
        rsp: [0; 3],
        reserved1: 0,
        ist: [0; 7],
        reserved2: 0,
        reserved3: 0,
        iomap_base: size_of::<Tss>() as u16,
    }),
    stacks: UnsafeCell::new([const { Stack([0; IST_STACK_SIZE]) }; 4]),
};

static LOADED: AtomicBool = AtomicBool::new(false);

/// A code or data descriptor. The base and the limit are not used in long mode.
const fn segment(access: u64, flags: u64) -> u64 {
    0xffff | (access << 40) | (0xf << 48) | (flags << 52)
}

#[repr(C, packed)]
struct Pointer {
    limit: u16,
    base: u64,
}

/// Fills the GDT and the TSS of the boot CPU, loads them and reloads the segment registers.
pub(crate) fn init() {
    if LOADED.swap(true, Ordering::AcqRel) {
        return;
    }
    let tss = TABLES.tss.get();
    let stacks = TABLES.stacks.get().cast::<Stack>();
    for (i, slot) in [IST_DOUBLE_FAULT, IST_NMI, IST_MACHINE_CHECK].into_iter().enumerate() {
        // The stack grows down, so the IST entry is the end of the stack.
        let top = stacks.wrapping_add(i + 1) as u64;
        // SAFETY: `LOADED` makes sure that this code runs one time, before the CPU uses the TSS.
        // No reference to the TSS exists.
        unsafe { (*tss).ist[usize::from(slot) - 1] = top };
    }
    let top = stacks.wrapping_add(ENTRY_STACK + 1) as u64;
    // SAFETY: as above, for RSP0.
    unsafe { (*tss).rsp[0] = top };

    let tss_base = tss as u64;
    let tss_limit = size_of::<Tss>() as u64 - 1;
    let gdt = TABLES.gdt.get();
    let entries: [u64; 10] = [
        0,
        segment(0x9b, 0xc), // 0x08: 32 bit kernel code
        segment(0x9b, 0xa), // 0x10: 64 bit kernel code
        segment(0x93, 0xc), // 0x18: kernel data
        segment(0xfb, 0xc), // 0x23: 32 bit user code
        segment(0xf3, 0xc), // 0x2b: user data
        segment(0xfb, 0xa), // 0x33: 64 bit user code
        0,                  // 0x38: not used
        (tss_limit & 0xffff)                // 0x40: the TSS, two slots
            | ((tss_base & 0xff_ffff) << 16)
            | (0x89 << 40)
            | (((tss_limit >> 16) & 0xf) << 48)
            | (((tss_base >> 24) & 0xff) << 56),
        tss_base >> 32,
    ];
    // SAFETY: as above, for the GDT.
    unsafe { gdt.write(entries) };

    let ptr = Pointer { limit: (size_of::<[u64; 10]>() - 1) as u16, base: gdt as u64 };
    // SAFETY: the GDT is static, so it lives for all of the run time. The kernel code and data
    // selectors have the same meaning as in the boot GDT, so the code that runs now continues to
    // work. The far return loads CS. The TSS descriptor is valid and not busy.
    unsafe {
        core::arch::asm!(
            "lgdt [{ptr}]",
            "push {cs}",
            "lea {tmp}, [rip + 2f]",
            "push {tmp}",
            "retfq",
            "2:",
            "mov ds, {ds:e}",
            "mov es, {ds:e}",
            "mov ss, {ds:e}",
            "xor {tmp:e}, {tmp:e}",
            "mov fs, {tmp:e}",
            "mov gs, {tmp:e}",
            "ltr {tss:x}",
            ptr = in(reg) &raw const ptr,
            cs = in(reg) u64::from(KERNEL_CS),
            ds = in(reg) u32::from(KERNEL_DS),
            tss = in(reg) TSS_SELECTOR,
            tmp = out(reg) _,
        );
    }
}
