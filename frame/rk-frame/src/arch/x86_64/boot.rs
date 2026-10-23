//! The entry points of the kernel image.
//!
//! The kernel has three entries, per spec/15-boot-and-platform.md section 15.3:
//!
//! - The PVH entry. QEMU, Firecracker and Cloud Hypervisor load an ELF kernel directly when it has
//!   a `XEN_ELFNOTE_PHYS32_ENTRY` note. Linux uses the same entry for the same loaders. The loader
//!   starts the CPU in 32 bit protected mode with paging off, and puts the physical address of a
//!   `hvm_start_info` structure in EBX.
//! - The 32 bit entry of the Linux boot protocol, at the start of the protected mode code of a
//!   bzImage. The loader puts the physical address of a `boot_params` structure in ESI. The real
//!   mode setup code in `setup.rs` also comes here.
//! - The 64 bit entry of the Linux boot protocol, 0x200 bytes after the 32 bit entry. The loader
//!   starts the CPU in long mode with an identity map, and puts `boot_params` in RSI. The EFI stub
//!   also comes here.
//!
//! The assembly below makes boot page tables that map the first 1 GiB of physical memory two
//! times: at address 0, and at the kernel base `0xffffffff80000000`. Then it turns on long mode,
//! moves to the kernel base and calls `rk_frame_x86_64_entry`. The identity map is only for the
//! boot path. `paging::init` replaces these tables with the kernel page tables.

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

    .section .boot.head, "ax"
    .code32
    .global rk_linux_start32
rk_linux_start32:                   # the 32 bit entry: ESI has boot_params
    movl %esi, %ebx
    movl ${linux}, %esi
    jmp rk_boot32

    .org 0x200
    .code64
    .global rk_linux_start64
rk_linux_start64:                   # the 64 bit entry: RSI has boot_params
    cli
    cld
    movq %rsi, %rbx
    movl $__bss_start_phys, %edi
    movl $__bss_end_phys, %ecx
    subl %edi, %ecx
    xorl %eax, %eax
    rep stosb
    movl %ebx, %edi
    movl ${linux}, %esi
    movl $0xc0000080, %ecx          # IA32_EFER
    rdmsr
    orl $0x800, %eax                # EFER.NXE. The loader set EFER.LME.
    wrmsr
    movq %cr0, %rax
    orl $0x10000, %eax              # CR0.WP
    movq %rax, %cr0
    movl $boot_pml4, %eax
    movq %rax, %cr3
    lgdt boot_gdt_ptr
    movl $boot_entry_stack_top, %esp  # the protocol does not give a stack
    pushq $0x08
    pushq $rk_boot64
    lretq

    .section .boot.text, "ax"
    .code32
    .global rk_pvh_start32
rk_pvh_start32:
    movl ${pvh}, %esi
rk_boot32:                          # EBX: the boot structure, ESI: the protocol
    cli
    cld
    movl $__bss_start_phys, %edi    # clear the bss: the loader does not have to clear it
    movl $__bss_end_phys, %ecx
    subl %edi, %ecx
    xorl %eax, %eax
    rep stosb
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
    movl %edi, %edi                 # the upper halves are not defined after the mode switch
    movl %esi, %esi
    movabsq $rk_boot64_high, %rax
    jmp *%rax

    .section .boot.data, "aw"
    .balign 8
boot_gdt:
    .quad 0
    .quad 0x00af9a000000ffff        # 0x08: 64 bit code, ring 0
    .quad 0x00cf92000000ffff        # 0x10: data, ring 0
boot_gdt_end:
boot_entry_stack:
    .skip 64
boot_entry_stack_top:
boot_gdt_ptr:
    .word boot_gdt_end - boot_gdt - 1
    .quad boot_gdt                  # lgdt reads 4 bytes of it in 32 bit mode and 8 in 64 bit mode

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
    pvh = const PROTOCOL_PVH,
    linux = const PROTOCOL_LINUX,
    options(att_syntax)
);

// The real mode setup code of the bzImage, per Documentation/arch/x86/boot.rst in the Linux tree.
// `cargo xtask` copies this section to the start of the bzImage and writes the setup header at
// offset 0x1f1. The section does not go into memory with the kernel, so each address in it is an
// offset from `rk_setup`. A BIOS loader such as QEMU puts the setup code at a segment boundary,
// sets DS to that segment and jumps to offset 0x200. The jump there goes to offset 0x280.
//
// The code makes `boot_params` at offset 0x8000 of the segment, gets the E820 memory map from the
// BIOS, goes to 32 bit protected mode and jumps to `code32_start` with ESI at `boot_params`. This
// global_asm! block is in the same module as the entry code, so the linker keeps it.
core::arch::global_asm!(
    r#"
    .section .rk_setup, "", @progbits
    .code16
rk_setup:
    .skip 0x280
    cli
    cld
    movw %ds, %ax
    movw %ax, %es
    movw %ax, %ss
    movw $0xf000, %sp
    pushw %ds                       # make CS the same as DS
    pushw $(1f - rk_setup)
    lretw
1:
    inb $0x92, %al                  # the fast A20 gate
    orb $0x02, %al
    andb $0xfe, %al
    outb %al, $0x92

    movw $0x8000, %di               # clear boot_params
    xorw %ax, %ax
    movw $2048, %cx
    rep stosw
    movw $0x1f1, %si                # copy the setup header that the loader changed
    movw $0x81f1, %di
    movw $(0x290 - 0x1f1), %cx
    rep movsb

    xorl %ebx, %ebx                 # the E820 memory map
    xorw %bp, %bp
    movw $0x82d0, %di
2:
    movl $0xe820, %eax
    movl $0x534d4150, %edx          # "SMAP"
    movl $20, %ecx
    int $0x15
    jc 3f
    cmpl $0x534d4150, %eax
    jne 3f
    incw %bp
    addw $20, %di
    testl %ebx, %ebx
    jz 3f
    cmpw $128, %bp
    jb 2b
3:
    movw %bp, %ax
    movb %al, 0x81e8

    xorl %eax, %eax                 # the linear address of the segment
    movw %ds, %ax
    sall $4, %eax
    leal 0x8000(%eax), %esi         # ESI: boot_params
    addl %eax, rk_setup_gdt_ptr + 2 - rk_setup
    lgdtl rk_setup_gdt_ptr - rk_setup
    movl 0x214, %eax                # code32_start
    movl %eax, rk_setup_pm_ptr - rk_setup
    movl %cr0, %eax
    orb $1, %al                     # CR0.PE
    movl %eax, %cr0
    movw $0x18, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs
    movw %ax, %ss
    xorl %ebx, %ebx
    xorl %edi, %edi
    xorl %ebp, %ebp
    ljmpl *%cs:rk_setup_pm_ptr - rk_setup

    .balign 8
rk_setup_gdt:
    .quad 0
    .quad 0
    .quad 0x00cf9a000000ffff        # 0x10: 32 bit code, ring 0
    .quad 0x00cf92000000ffff        # 0x18: data, ring 0
rk_setup_gdt_end:
rk_setup_gdt_ptr:
    .word rk_setup_gdt_end - rk_setup_gdt - 1
    .long rk_setup_gdt - rk_setup   # the code adds the linear address of the segment
rk_setup_pm_ptr:
    .long 0
    .word 0x10
    .code64
"#,
    options(att_syntax)
);

/// The entry code gives one of these values to `rk_frame_x86_64_entry`.
const PROTOCOL_PVH: u32 = 0;
const PROTOCOL_LINUX: u32 = 1;

/// The value of `hvm_start_info.magic`.
const PVH_MAGIC: u32 = 0x336e_c578;

/// The boot page tables map physical memory below this address at address 0.
const BOOT_IDENTITY_LIMIT: u64 = 1 << 30;

/// The first Rust code. The assembly above calls it on the boot stack.
#[unsafe(no_mangle)]
extern "C" fn rk_frame_x86_64_entry(boot: u64, protocol: u32) -> ! {
    super::serial::init();
    super::init_cpu();
    let info = if protocol == PROTOCOL_LINUX {
        super::boot_params::read(boot)
    } else {
        let mut info = BootInfo::new("pvh");
        read_start_info(boot, &mut info);
        info
    };
    crate::mm::frame::init(&info, super::paging::kernel_end_phys());
    super::paging::init(&info);
    super::apic::init();
    crate::boot::start(info)
}

/// Reads one value from physical memory through the boot identity map. Gives `None` for an address
/// that the map does not cover.
pub(super) fn read_phys<T: Copy>(addr: u64) -> Option<T> {
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
