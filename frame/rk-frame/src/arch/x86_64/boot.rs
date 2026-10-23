//! The PVH entry point.
//!
//! QEMU, Firecracker and Cloud Hypervisor load an ELF kernel directly when it has a
//! `XEN_ELFNOTE_PHYS32_ENTRY` note, per spec/15-boot-and-platform.md section 15.3. Linux uses the
//! same entry for the same loaders. The loader starts the CPU in 32 bit protected mode with paging
//! off, and puts the physical address of a `hvm_start_info` structure in EBX.
//!
//! The assembly below makes boot page tables that map the first 1 GiB of physical memory two
//! times: at address 0, and at the kernel base `0xffffffff80000000`. Then it turns on long mode,
//! moves to the kernel base and calls `rk_frame_x86_64_entry`. The identity map is only for the
//! boot path. The kernel page tables replace these tables in R0.

use crate::addr::PhysAddr;
use crate::boot::{BootInfo, MemoryKind};

core::arch::global_asm!(
    r#"
    .section .note.Xen, "a", @note
    .balign 4
    .long 4                         # namesz
    .long 8                         # descsz
    .long 18                        # XEN_ELFNOTE_PHYS32_ENTRY
    .asciz "Xen"
    .balign 4
    .quad rk_pvh_start32
    .balign 4

    .section .boot.text, "ax"
    .code32
    .global rk_pvh_start32
rk_pvh_start32:
    cli
    cld
    movl %ebx, %edi                 # the physical address of hvm_start_info
    movl $boot_pml4, %eax
    movl %eax, %cr3
    movl %cr4, %eax
    orl $0x20, %eax                 # CR4.PAE
    movl %eax, %cr4
    movl $0xc0000080, %ecx          # IA32_EFER
    rdmsr
    orl $0x900, %eax                # EFER.LME and EFER.NXE
    wrmsr
    movl %cr0, %eax
    orl $0x80010001, %eax           # CR0.PG, CR0.WP and CR0.PE
    movl %eax, %cr0
    lgdt boot_gdt_ptr
    ljmp $0x08, $rk_boot64

    .code64
rk_boot64:
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss
    xorw %ax, %ax
    movw %ax, %fs
    movw %ax, %gs
    movl %edi, %edi                 # the upper half of RDI is not defined after the mode switch
    movabsq $rk_boot64_high, %rax
    jmp *%rax

    .section .boot.data, "aw"
    .balign 8
boot_gdt:
    .quad 0
    .quad 0x00af9a000000ffff        # 0x08: 64 bit code, ring 0
    .quad 0x00cf92000000ffff        # 0x10: data, ring 0
boot_gdt_end:
boot_gdt_ptr:
    .word boot_gdt_end - boot_gdt - 1
    .long boot_gdt

    .balign 4096
boot_pml4:
    .quad boot_pdpt_low + 0x3
    .fill 510, 8, 0
    .quad boot_pdpt_high + 0x3
boot_pdpt_low:
    .quad boot_pd + 0x3
    .fill 511, 8, 0
boot_pdpt_high:
    .fill 510, 8, 0
    .quad boot_pd + 0x3
    .quad 0
boot_pd:                            # 512 pages of 2 MiB: present, writable, large
    .set rk_page, 0
    .rept 512
    .quad (rk_page << 21) + 0x83
    .set rk_page, rk_page + 1
    .endr

    .section .text.rk_boot64_high, "ax"
rk_boot64_high:
    leaq boot_stack_top(%rip), %rsp
    xorl %ebp, %ebp
    call rk_frame_x86_64_entry
    ud2

    .section .bss.boot_stack, "aw", @nobits
    .balign 16
boot_stack:
    .skip 65536
boot_stack_top:
"#,
    options(att_syntax)
);

/// The value of `hvm_start_info.magic`.
const PVH_MAGIC: u32 = 0x336e_c578;

/// The boot page tables map physical memory below this address at address 0.
const BOOT_IDENTITY_LIMIT: u64 = 1 << 30;

/// The first Rust code. The assembly above calls it on the boot stack.
#[unsafe(no_mangle)]
extern "C" fn rk_frame_x86_64_entry(start_info: u64) -> ! {
    super::serial::init();
    super::init_cpu();
    let mut info = BootInfo::new("pvh");
    read_start_info(start_info, &mut info);
    crate::boot::start(info)
}

/// Reads one value from physical memory through the boot identity map. Gives `None` for an address
/// that the map does not cover.
fn read_phys<T: Copy>(addr: u64) -> Option<T> {
    let end = addr.checked_add(size_of::<T>() as u64)?;
    if addr == 0 || end > BOOT_IDENTITY_LIMIT {
        return None;
    }
    // SAFETY: the boot page tables map all of the first 1 GiB at address 0, and the check above
    // keeps the read inside it. The value is read unaligned and copied out, so no reference to the
    // memory remains. A `T` here is a plain integer structure, for which each bit pattern is valid.
    Some(unsafe { core::ptr::read_unaligned(addr as *const T) })
}

#[repr(C)]
#[derive(Clone, Copy)]
struct StartInfo {
    magic: u32,
    version: u32,
    flags: u32,
    nr_modules: u32,
    modlist_paddr: u64,
    cmdline_paddr: u64,
    rsdp_paddr: u64,
    memmap_paddr: u64,
    memmap_entries: u32,
    reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct MemmapEntry {
    addr: u64,
    size: u64,
    kind: u32,
    reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ModlistEntry {
    paddr: u64,
    size: u64,
    cmdline_paddr: u64,
    reserved: u64,
}

fn read_start_info(addr: u64, info: &mut BootInfo) {
    let Some(si) = read_phys::<StartInfo>(addr) else { return };
    if si.magic != PVH_MAGIC {
        return;
    }
    if si.cmdline_paddr != 0 {
        let mut p = si.cmdline_paddr;
        while let Some(b) = read_phys::<u8>(p) {
            if b == 0 || !info.push_cmdline_byte(b) {
                break;
            }
            p += 1;
        }
    }
    if si.rsdp_paddr != 0 {
        info.set_rsdp(PhysAddr::new(si.rsdp_paddr));
    }
    if si.nr_modules > 0
        && let Some(m) = read_phys::<ModlistEntry>(si.modlist_paddr)
    {
        info.set_initrd(PhysAddr::new(m.paddr), m.size);
    }
    // The memory map is in version 1 and later of the structure.
    if si.version >= 1 {
        for i in 0..u64::from(si.memmap_entries) {
            let at = si.memmap_paddr + i * size_of::<MemmapEntry>() as u64;
            let Some(e) = read_phys::<MemmapEntry>(at) else { break };
            info.push_region(PhysAddr::new(e.addr), e.size, MemoryKind::from_e820(e.kind));
        }
    }
}
