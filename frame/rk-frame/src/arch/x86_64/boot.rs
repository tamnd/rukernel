//! The entry points of the kernel image.
//!
//! The kernel has four entries, per spec/15-boot-and-platform.md section 15.3:
//!
//! - The PVH entry. QEMU, Firecracker and Cloud Hypervisor load an ELF kernel directly when it has
//!   a `XEN_ELFNOTE_PHYS32_ENTRY` note. Linux uses the same entry for the same loaders. The loader
//!   starts the CPU in 32 bit protected mode with paging off, and puts the physical address of a
//!   `hvm_start_info` structure in EBX.
//! - The 32 bit entry of the Linux boot protocol, at the start of the protected mode code of a
//!   bzImage. The loader puts the physical address of a `boot_params` structure in ESI. The real
//!   mode setup code in the `.rk_setup` section also comes here.
//! - The 64 bit entry of the Linux boot protocol, 0x200 bytes after the 32 bit entry. The loader
//!   starts the CPU in long mode with an identity map, and puts `boot_params` in RSI. The EFI stub
//!   also comes here.
//! - The EFI stub, 0x400 bytes after the 32 bit entry. It is the entry point of the PE image.
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

    # The EFI stub, at the entry point of the PE image. The firmware can load the image at any
    # address, so the code uses only RIP relative addresses until it jumps to the copy of the
    # kernel at 1 MiB. The calls use the Microsoft x64 convention of UEFI.
    .org 0x400
    .global rk_efi_entry
rk_efi_entry:                       # RCX: the image handle, RDX: the system table
    pushq %rbx
    pushq %rbp
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    subq $0x68, %rsp                # the shadow space, a stack argument and the variables
    movq %rcx, %r12
    movq %rdx, %r13
    movq 0x60(%r13), %r14           # the boot services

    movq $0x100000, 0x30(%rsp)      # the pages of the kernel, at 1 MiB
    movl $2, %ecx                   # AllocateAddress
    movl $2, %edx                   # EfiLoaderData
    movl $__kernel_pages_phys, %r8d
    leaq 0x30(%rsp), %r9
    call *0x28(%r14)                # AllocatePages
    testq %rax, %rax
    jnz 9f

    movq $0x3fffffff, 0x30(%rsp)    # the boot data, below the 1 GiB that the boot page tables map
    movl $1, %ecx                   # AllocateMaxAddress
    movl $2, %edx                   # EfiLoaderData
    movl $16, %r8d
    leaq 0x30(%rsp), %r9
    call *0x28(%r14)                # AllocatePages
    testq %rax, %rax
    jnz 9f
    movq 0x30(%rsp), %r15           # boot_params, the command line at 0x1000, the map at 0x2000
    movq %r15, %rdi
    movl $0x10000, %ecx
    xorl %eax, %eax
    rep stosb

    leaq rk_linux_start32(%rip), %rsi   # copy the kernel to 1 MiB
    movl $0x100000, %edi
    movl $__bss_start_phys, %ecx
    subl %edi, %ecx
    rep movsb
    leaq rk_linux_start32 - 0x1000 + 0x1f1(%rip), %rsi  # the setup header, in the PE headers
    leaq 0x1f1(%r15), %rdi
    movl $0x290 - 0x1f1, %ecx
    rep movsb

    movq %r12, %rcx                 # the command line, from the load options
    leaq rk_efi_loaded_image_guid(%rip), %rdx
    leaq 0x30(%rsp), %r8
    call *0x98(%r14)                # HandleProtocol
    testq %rax, %rax
    jnz 3f
    movq 0x30(%rsp), %rax
    movl 0x30(%rax), %ecx           # LoadOptionsSize, in bytes
    movq 0x38(%rax), %rsi           # LoadOptions, UTF-16
    shrl $1, %ecx
    cmpl $2047, %ecx
    jbe 1f
    movl $2047, %ecx
1:
    leaq 0x1000(%r15), %rdi
    movl %edi, 0x228(%r15)          # cmd_line_ptr
    testq %rsi, %rsi
    jz 3f
2:
    testl %ecx, %ecx
    jz 3f
    movzwl (%rsi), %eax
    testl %eax, %eax
    jz 3f
    cmpl $0x7f, %eax
    jbe 4f
    movl $0x3f, %eax                # "?" for a character that is not ASCII
4:
    movb %al, (%rdi)
    addq $2, %rsi
    incq %rdi
    decl %ecx
    jmp 2b
3:

    # The initramfs, from the LoadFile2 protocol on the initrd media device path, as the EFI stub
    # of Linux gets it. QEMU writes the address of its own copy in the setup header, but the
    # firmware can use that memory, so the stub clears the fields first.
    movq $0, 0x218(%r15)            # ramdisk_image and ramdisk_size
    leaq rk_efi_initrd_path(%rip), %rax
    movq %rax, 0x58(%rsp)
    leaq rk_efi_load_file2_guid(%rip), %rcx
    leaq 0x58(%rsp), %rdx
    leaq 0x60(%rsp), %r8
    call *0xb8(%r14)                # LocateDevicePath
    testq %rax, %rax
    jnz 8f
    movq 0x60(%rsp), %rcx
    leaq rk_efi_load_file2_guid(%rip), %rdx
    leaq 0x28(%rsp), %r8
    call *0x98(%r14)                # HandleProtocol
    testq %rax, %rax
    jnz 8f
    movq $0, 0x38(%rsp)             # ask for the size
    movq 0x28(%rsp), %rcx
    movq 0x58(%rsp), %rdx
    xorl %r8d, %r8d
    leaq 0x38(%rsp), %r9
    movq $0, 0x20(%rsp)
    call *(%rcx)                    # LoadFile
    movq 0x38(%rsp), %rbp
    testq %rbp, %rbp
    jz 8f
    movq $0x7fffffff, 0x30(%rsp)    # initrd_addr_max of the setup header
    movl $1, %ecx                   # AllocateMaxAddress
    movl $2, %edx                   # EfiLoaderData
    leaq 0xfff(%rbp), %r8
    shrq $12, %r8
    leaq 0x30(%rsp), %r9
    call *0x28(%r14)                # AllocatePages
    testq %rax, %rax
    jnz 8f
    movq 0x28(%rsp), %rcx
    movq 0x58(%rsp), %rdx
    xorl %r8d, %r8d
    leaq 0x38(%rsp), %r9
    movq 0x30(%rsp), %rax
    movq %rax, 0x20(%rsp)
    call *(%rcx)                    # LoadFile
    testq %rax, %rax
    jnz 8f
    movq 0x30(%rsp), %rax
    movl %eax, 0x218(%r15)          # ramdisk_image
    movq 0x38(%rsp), %rax
    movl %eax, 0x21c(%r15)          # ramdisk_size
8:

    leaq rk_efi_acpi20_guid(%rip), %rdi # the ACPI RSDP, from the configuration table
    call rk_efi_find_table
    testq %rax, %rax
    jnz 5f
    leaq rk_efi_acpi10_guid(%rip), %rdi
    call rk_efi_find_table
5:
    movq %rax, 0x070(%r15)          # acpi_rsdp_addr

    movl $2, %ebx                   # the memory map. ExitBootServices can fail one time
6:
    movq $0xe000, 0x38(%rsp)
    leaq 0x38(%rsp), %rcx
    leaq 0x2000(%r15), %rdx
    leaq 0x40(%rsp), %r8
    leaq 0x48(%rsp), %r9
    leaq 0x50(%rsp), %rax
    movq %rax, 0x20(%rsp)
    call *0x38(%r14)                # GetMemoryMap
    testq %rax, %rax
    jnz 9f
    movq %r12, %rcx
    movq 0x40(%rsp), %rdx
    call *0xe8(%r14)                # ExitBootServices
    testq %rax, %rax
    jz 7f
    decl %ebx
    jnz 6b
    jmp 9f
7:
    cli
    movl $0x34364c45, 0x1c0(%r15)   # efi_loader_signature: "EL64"
    movq %r13, %rax
    movl %eax, 0x1c4(%r15)          # efi_systab
    shrq $32, %rax
    movl %eax, 0x1d8(%r15)          # efi_systab_hi
    movq 0x48(%rsp), %rax
    movl %eax, 0x1c8(%r15)          # efi_memdesc_size
    movl 0x50(%rsp), %eax
    movl %eax, 0x1cc(%r15)          # efi_memdesc_version
    leaq 0x2000(%r15), %rax
    movl %eax, 0x1d0(%r15)          # efi_memmap
    movq 0x38(%rsp), %rax
    movl %eax, 0x1d4(%r15)          # efi_memmap_size
    movq %r15, %rsi
    movl $rk_linux_start64, %eax
    jmp *%rax

9:
    movabsq $0x8000000000000001, %rax   # EFI_LOAD_ERROR
    addq $0x68, %rsp
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rbp
    popq %rbx
    ret

rk_efi_find_table:                  # RDI: a GUID. Gives the table in RAX, or 0
    movq 0x68(%r13), %rcx           # NumberOfTableEntries
    movq 0x70(%r13), %rdx           # ConfigurationTable
1:
    testq %rcx, %rcx
    jz 2f
    movq (%rdx), %rax
    cmpq (%rdi), %rax
    jne 3f
    movq 8(%rdx), %rax
    cmpq 8(%rdi), %rax
    jne 3f
    movq 16(%rdx), %rax
    ret
3:
    addq $24, %rdx
    decq %rcx
    jmp 1b
2:
    xorl %eax, %eax
    ret

    .balign 8
rk_efi_loaded_image_guid:           # 5b1b31a1-9562-11d2-8e3f-00a0c969723b
    .long 0x5b1b31a1
    .word 0x9562, 0x11d2
    .byte 0x8e, 0x3f, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b
rk_efi_acpi20_guid:                 # 8868e871-e4f1-11d3-bc22-0080c73c8881
    .long 0x8868e871
    .word 0xe4f1, 0x11d3
    .byte 0xbc, 0x22, 0x00, 0x80, 0xc7, 0x3c, 0x88, 0x81
rk_efi_acpi10_guid:                 # eb9d2d30-2d88-11d3-9a16-0090273fc14d
    .long 0xeb9d2d30
    .word 0x2d88, 0x11d3
    .byte 0x9a, 0x16, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d
rk_efi_load_file2_guid:             # 4006c0c1-fcb3-403e-996d-4a6c8724e06d
    .long 0x4006c0c1
    .word 0xfcb3, 0x403e
    .byte 0x99, 0x6d, 0x4a, 0x6c, 0x87, 0x24, 0xe0, 0x6d
rk_efi_initrd_path:                 # a vendor media node and the end node
    .byte 4, 3
    .word 20
    .long 0x5568e427                # LINUX_EFI_INITRD_MEDIA_GUID
    .word 0x68fc, 0x4f3d
    .byte 0xac, 0x74, 0xca, 0x55, 0x52, 0x31, 0xcc, 0x68
    .byte 0x7f, 0xff
    .word 4

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
    match si.rsdp_paddr {
        0 => {
            if let Some(rsdp) = super::boot_params::find_rsdp() {
                info.set_rsdp(PhysAddr::new(rsdp));
            }
        }
        rsdp => info.set_rsdp(PhysAddr::new(rsdp)),
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
