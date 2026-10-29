//! The other CPUs: their start, and the interrupts between CPUs.
//!
//! The ACPI MADT gives the local APIC ID of each CPU. The boot CPU starts the other CPUs one at a
//! time with the INIT and STARTUP interrupts, as Linux does in `do_boot_cpu`. A CPU starts in real
//! mode at the code that `rk_ap_trampoline` gives, which the boot CPU copies to `TRAMPOLINE`. That
//! code goes to long mode with page tables in the pages after it, and calls `ap_entry` on the
//! stack that the boot CPU gives.
//!
//! A CPU sends `CALL_VECTOR` to tell other CPUs to drop a TLB entry, and `RESCHEDULE_VECTOR` to wake
//! a CPU that waits for an interrupt.

use super::{apic, cpu, paging};
use crate::addr::PAGE_SIZE;
use crate::sync::SpinLock;
use alloc::alloc::{Layout, alloc};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// The vector that tells a CPU to drop a TLB entry. Linux names it `CALL_FUNCTION_VECTOR`.
pub(crate) const CALL_VECTOR: u8 = 0xfc;
/// The vector that wakes a CPU. Linux names it `RESCHEDULE_VECTOR`.
pub(crate) const RESCHEDULE_VECTOR: u8 = 0xfd;

/// Tells if `vector` is an interrupt from another CPU.
pub(crate) fn is_ipi(vector: u8) -> bool {
    matches!(vector, CALL_VECTOR | RESCHEDULE_VECTOR)
}

/// Handles an interrupt from another CPU. Gives `false` for another vector.
pub(crate) fn handle(vector: u8) -> bool {
    match vector {
        CALL_VECTOR => poll(),
        RESCHEDULE_VECTOR => {}
        _ => return false,
    }
    apic::eoi();
    true
}

/// The address in `FLUSH_ADDR` that tells each CPU to stop the use of the address space.
pub(crate) const LEAVE: u64 = u64::MAX;
/// The address in `FLUSH_ADDR` that tells each CPU to do nothing. The interrupt is a full
/// memory barrier, which `membarrier(2)` needs.
pub(crate) const BARRIER: u64 = u64::MAX - 1;
/// The address in `FLUSH_ADDR` that tells each CPU to drop all the TLB entries of user pages.
pub(crate) const FLUSH_ALL: u64 = u64::MAX - 2;

/// One request at a time goes to the other CPUs.
static FLUSH: SpinLock<()> = SpinLock::new(());
/// The address space of the request, or 0 for a kernel address.
static FLUSH_ROOT: AtomicU64 = AtomicU64::new(0);
/// The page of the request, or `LEAVE`.
static FLUSH_ADDR: AtomicU64 = AtomicU64::new(0);
/// The number of pages from `FLUSH_ADDR` that the request drops.
static FLUSH_PAGES: AtomicU64 = AtomicU64::new(1);
/// The CPUs that did not do the request yet.
static PENDING: AtomicU64 = AtomicU64::new(0);

/// Tells each other CPU that uses the address space `root` to drop the TLB entry of `addr`. A
/// `root` of 0 is for a kernel address, and each CPU drops the entry. An `addr` of `LEAVE` tells
/// each CPU that uses `root` to load the kernel page table. The function returns when each of
/// these CPUs did it.
pub(crate) fn shootdown(root: u64, addr: u64) {
    shootdown_range(root, addr, 1);
}

/// Tells each other CPU that uses the address space `root` to drop the TLB entries of `pages`
/// pages from `addr`, with one interrupt for the range, as `flush_tlb_kernel_range` of Linux. A
/// special `addr` such as `LEAVE` does its request one time. The function returns when each of
/// these CPUs did it.
pub(crate) fn shootdown_range(root: u64, addr: u64, pages: u64) {
    let me = cpu::id();
    // The change of the page table comes before the read of the address space of each CPU, and
    // `paging::activate` changes the address space before it loads the table. Thus a CPU that is
    // not in the mask loads the table after the change, and has no old TLB entry.
    core::sync::atomic::fence(Ordering::SeqCst);
    let mask = (0..cpu::count())
        .filter(|&c| c != me && (root == 0 || paging::active_on(c) == root))
        .fold(0u64, |m, c| m | 1 << c);
    if mask == 0 {
        return;
    }
    let _guard = loop {
        if let Some(guard) = FLUSH.try_lock() {
            break guard;
        }
        poll();
        core::hint::spin_loop();
    };
    FLUSH_ROOT.store(root, Ordering::Relaxed);
    FLUSH_ADDR.store(addr, Ordering::Relaxed);
    FLUSH_PAGES.store(pages, Ordering::Relaxed);
    PENDING.store(mask, Ordering::Release);
    for c in (0..cpu::count()).filter(|c| mask & 1 << c != 0) {
        apic::send_ipi(cpu::apic_id(c), u32::from(CALL_VECTOR));
    }
    while PENDING.load(Ordering::Acquire) != 0 {
        core::hint::spin_loop();
    }
}

/// Does the request of `shootdown` if this CPU has one. The interrupt handler calls it, and so
/// does each loop that waits with interrupts off for another CPU.
pub(crate) fn poll() {
    let bit = 1u64 << cpu::id();
    if PENDING.load(Ordering::Acquire) & bit == 0 {
        return;
    }
    let root = FLUSH_ROOT.load(Ordering::Relaxed);
    let addr = FLUSH_ADDR.load(Ordering::Relaxed);
    if addr == LEAVE {
        paging::leave(root);
    } else if addr == BARRIER {
        core::sync::atomic::fence(Ordering::SeqCst);
    } else if addr == FLUSH_ALL {
        paging::flush_user_all();
    } else {
        let pages = FLUSH_PAGES.load(Ordering::Relaxed);
        for i in 0..pages {
            paging::flush((addr + i * PAGE_SIZE as u64) as usize);
        }
    }
    PENDING.fetch_and(!bit, Ordering::Release);
}

/// Wakes the CPU `id` if it waits for an interrupt.
pub(crate) fn reschedule(id: usize) {
    apic::send_ipi(cpu::apic_id(id), u32::from(RESCHEDULE_VECTOR));
}

/// The physical address of the start code of the other CPUs. The STARTUP interrupt gives the page
/// number, so the address is below 1 MiB and page aligned. The three pages after it hold the page
/// tables of the start code. The loaders put nothing at these addresses.
const TRAMPOLINE: u64 = 0x8000;
/// The offsets in the code page of the values that the boot CPU writes for each CPU.
const SLOT_STACK: u64 = 0xff0;
const SLOT_ENTRY: u64 = 0xff8;

// The start code of the other CPUs. The boot CPU copies it to `TRAMPOLINE`, so each address in it
// is `TRAMPOLINE` plus an offset from `rk_ap_trampoline`. The page tables at `TRAMPOLINE + 0x1000`
// map the first 2 MiB at address 0 and have the kernel half of the kernel page tables.
core::arch::global_asm!(
    r#"
    .section .rodata.rk_ap_trampoline, "a"
    .code16
    .global rk_ap_trampoline
rk_ap_trampoline:
    cli
    cld
    xorw %ax, %ax
    movw %ax, %ds
    lgdtl {base} + (rk_ap_gdt_ptr - rk_ap_trampoline)
    movl %cr0, %eax
    orl $1, %eax                    # CR0.PE
    movl %eax, %cr0
    ljmpl $0x08, ${base} + (1f - rk_ap_trampoline)

    .code32
1:
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss
    movl %cr4, %eax
    orl $0xa0, %eax                 # CR4.PAE and CR4.PGE
    movl %eax, %cr4
    movl ${base} + 0x1000, %eax
    movl %eax, %cr3
    movl $0xc0000080, %ecx          # IA32_EFER
    rdmsr
    orl $0x900, %eax                # EFER.LME and EFER.NXE
    wrmsr
    movl %cr0, %eax
    orl $0x80010001, %eax           # CR0.PG, CR0.WP and CR0.PE
    movl %eax, %cr0
    ljmpl $0x18, ${base} + (2f - rk_ap_trampoline)

    .code64
2:
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss
    movq {base} + {stack}, %rsp
    movq {base} + {entry}, %rax
    xorl %ebp, %ebp
    callq *%rax
    ud2

    .balign 8
rk_ap_gdt:
    .quad 0
    .quad 0x00cf9a000000ffff        # 0x08: 32 bit code
    .quad 0x00cf92000000ffff        # 0x10: data
    .quad 0x00af9a000000ffff        # 0x18: 64 bit code
rk_ap_gdt_ptr:
    .word rk_ap_gdt_ptr - rk_ap_gdt - 1
    .long {base} + (rk_ap_gdt - rk_ap_trampoline)
    .global rk_ap_trampoline_end
rk_ap_trampoline_end:
"#,
    base = const TRAMPOLINE,
    stack = const SLOT_STACK,
    entry = const SLOT_ENTRY,
    options(att_syntax)
);

unsafe extern "C" {
    static rk_ap_trampoline: u8;
    static rk_ap_trampoline_end: u8;
}

/// The CPU that starts sets this when it runs in the kernel.
static STARTED: AtomicBool = AtomicBool::new(false);

/// The ICR values of the INIT and STARTUP interrupts: the delivery mode and the level assert bit.
const ICR_INIT: u32 = 0x4500;
const ICR_STARTUP: u32 = 0x4600;

/// Waits `us` microseconds.
fn delay(us: u64) {
    let end = apic::nanos() + us * 1000;
    while apic::nanos() < end {
        core::hint::spin_loop();
    }
}

/// Writes the code and the page tables of the start code to low memory.
fn write_trampoline() {
    let start = &raw const rk_ap_trampoline;
    let end = &raw const rk_ap_trampoline_end;
    let len = end as usize - start as usize;
    assert!(len <= SLOT_STACK as usize, "the start code is too large");
    let code = paging::phys_to_virt(TRAMPOLINE) as *mut u8;
    // SAFETY: the direct map has the first 1 MiB, and the frame allocator does not use it, so the
    // four pages at `TRAMPOLINE` belong to this code. The start code is `len` bytes of read only
    // data in the kernel image.
    unsafe { super::mem::copy(code, start, len) };
    let table = |n: u64| paging::phys_to_virt(TRAMPOLINE + n * 0x1000) as *mut u64;
    // SAFETY: as above. Each table is one page of 512 entries.
    unsafe {
        super::mem::zero(table(1).cast(), 3 * 0x1000);
        table(1).write(TRAMPOLINE + 0x2000 | 0x3);
        table(2).write(TRAMPOLINE + 0x3000 | 0x3);
        table(3).write(0x83); // 2 MiB at address 0: present, writable, large
    }
    paging::copy_kernel_half(TRAMPOLINE + 0x1000);
}

/// Starts the CPU with the number `id` and the local APIC ID `apic_id`, and waits until it runs.
/// Gives `false` if it does not start.
fn start_cpu(id: usize, apic_id: u32) -> bool {
    let layout = Layout::from_size_align(crate::task::KERNEL_STACK_SIZE, 16)
        .unwrap_or_else(|_| panic!("the stack layout is not valid"));
    // SAFETY: the layout has a size that is not zero.
    let stack = unsafe { alloc(layout) };
    if stack.is_null() {
        return false;
    }
    NEXT_ID.store(id as u64, Ordering::Relaxed);
    NEXT_APIC_ID.store(u64::from(apic_id), Ordering::Relaxed);
    STARTED.store(false, Ordering::Release);
    let slot = |off: u64| paging::phys_to_virt(TRAMPOLINE + off) as *mut u64;
    // SAFETY: the slots are in the code page of the start code, after the code. The stack is new
    // and stays for all of the run time, because the CPU runs on it until it stops.
    unsafe {
        slot(SLOT_STACK).write(stack as u64 + crate::task::KERNEL_STACK_SIZE as u64);
        slot(SLOT_ENTRY).write(ap_entry as *const () as u64);
    }
    apic::send_ipi(apic_id, ICR_INIT);
    delay(10_000);
    for _ in 0..2 {
        apic::send_ipi(apic_id, ICR_STARTUP | (TRAMPOLINE >> 12) as u32);
        let end = apic::nanos() + 1_000_000_000;
        while apic::nanos() < end {
            if STARTED.load(Ordering::Acquire) {
                return true;
            }
            core::hint::spin_loop();
        }
    }
    false
}

/// The number and the local APIC ID of the CPU that starts.
static NEXT_ID: AtomicU64 = AtomicU64::new(0);
static NEXT_APIC_ID: AtomicU64 = AtomicU64::new(0);

/// The first Rust code of a CPU that is not the boot CPU. The start code calls it on the stack
/// of the CPU, with the page tables of the start code.
extern "C" fn ap_entry() -> ! {
    let id = NEXT_ID.load(Ordering::Relaxed) as usize;
    let apic_id = NEXT_APIC_ID.load(Ordering::Relaxed) as u32;
    // The heap finds the free lists of this CPU with `cpu::id`, so the GS base must be set before
    // the tables are allocated. The load of the GDT sets GS to 0, so it is set again after it.
    cpu::init(id, apic_id);
    super::gdt::init_secondary(id);
    cpu::init(id, apic_id);
    super::idt::load();
    super::user::init();
    paging::activate(0);
    apic::init_secondary();
    cpu::add_online();
    STARTED.store(true, Ordering::Release);
    crate::task::run_secondary()
}

/// Starts each CPU that the ACPI MADT gives, up to `cpu::MAX_CPUS`. Gives the number of CPUs that
/// run.
pub(crate) fn start_cpus() -> usize {
    let me = apic::id();
    cpu::init(0, me);
    let mut ids = [0u32; cpu::MAX_CPUS];
    let n = super::acpi::local_apic_ids(&mut ids);
    let others: alloc::vec::Vec<u32> = ids[..n].iter().copied().filter(|&a| a != me).collect();
    if others.is_empty() {
        return cpu::count();
    }
    write_trampoline();
    for apic_id in others {
        let id = cpu::count();
        if id >= cpu::MAX_CPUS {
            break;
        }
        if !start_cpu(id, apic_id) {
            crate::console::_print_panic(format_args!(
                "rk-frame: CPU with APIC ID {apic_id} does not start\n"
            ));
        }
    }
    cpu::count()
}
