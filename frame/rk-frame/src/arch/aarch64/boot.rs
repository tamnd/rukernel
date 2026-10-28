//! The entry point of the arm64 kernel image.
//!
//! The image is a Linux arm64 `Image`, per spec/15-boot-and-platform.md section 15.3 and
//! Documentation/arch/arm64/booting.rst of Linux. QEMU `-kernel`, U-Boot `booti`, GRUB and the EFI
//! stub of a later step all load this format, so one image works on QEMU and on real firmware. The
//! 64 byte header at the start tells the loader the size of the image and that it can go at any 2
//! MiB aligned address. The loader starts the CPU at the first byte, at EL2 or EL1, with the MMU
//! off, and puts the physical address of the device tree in x0.
//!
//! The kernel is linked at `KERNEL_BASE`, but the loader can put it at any physical address. The
//! assembly below uses only addresses relative to the PC until the MMU is on. It makes the boot
//! page tables:
//!
//! - TTBR0: an identity map of the 1 GiB that holds the start of the image. The code that turns
//!   the MMU on runs there.
//! - TTBR1: the image at `KERNEL_BASE` with 4 KiB pages and the permissions of each section, the
//!   1 GiB blocks of the direct map that hold the image and the device tree, and the device window
//!   at `MMIO_BASE`.
//!
//! Then it turns the MMU on, jumps to `KERNEL_BASE`, turns off the walks of TTBR0, clears the bss
//! and calls `rk_frame_aarch64_entry` on the boot stack.

use super::paging;
use crate::boot::BootInfo;

/// The flags field of the image header: little endian, 4 KiB pages, and any physical address.
const IMAGE_FLAGS: u64 = (1 << 1) | (1 << 3);

/// The number of level 3 tables for the kernel image. Each maps 2 MiB. The linker script checks
/// that the image fits.
const IMAGE_L3_TABLES: usize = 32;

/// The size of the boot stack.
const BOOT_STACK_SIZE: usize = 64 * 1024;

core::arch::global_asm!(
    r#"
    .section .head.text, "ax"
    .global _head
_head:
    b       rk_aarch64_primary          // code0
    .long   0                           // code1
    .quad   0                           // text_offset
    .quad   __image_size                // image_size
    .quad   {flags}                     // flags
    .quad   0                           // res2
    .quad   0                           // res3
    .quad   0                           // res4
    .long   0x644d5241                  // magic, "ARM\x64"
    .long   0                           // res5, the offset of the PE header

rk_aarch64_primary:
    mov     x19, x0                     // the physical address of the device tree
    adr     x20, _head                  // the physical address of the image

    // The protocol allows EL2. The kernel runs at EL1, so EL2 lets EL1 use the timers and the FP
    // and SIMD registers, and returns to the code below at EL1.
    mrs     x1, CurrentEL
    cmp     x1, #(2 << 2)
    b.ne    1f
    mov     x1, #(1 << 31)              // HCR_EL2.RW: EL1 runs in AArch64
    msr     hcr_el2, x1
    mrs     x1, cnthctl_el2
    orr     x1, x1, #3                  // EL1PCTEN and EL1PCEN
    msr     cnthctl_el2, x1
    msr     cntvoff_el2, xzr
    mov     x1, #0x33ff                 // CPTR_EL2: the RES1 bits, and no trap of FP and SIMD
    msr     cptr_el2, x1
    msr     hstr_el2, xzr
    ldr     x1, ={sctlr_off}
    msr     sctlr_el1, x1
    mov     x1, #0x3c5                  // EL1h with D, A, I and F masked
    msr     spsr_el2, x1
    adr     x1, 1f
    msr     elr_el2, x1
    eret

1:  ldr     x1, ={sctlr_off}
    msr     sctlr_el1, x1
    isb
    mov     x1, #(3 << 20)              // CPACR_EL1.FPEN: the kernel code uses SIMD registers
    msr     cpacr_el1, x1
    isb

    // The caches are off, so the writes below go to memory. A cache line of the loader can hold
    // old data for the tables, so the lines are invalidated before and after the writes.
    adrp    x1, __boot_tables_start
    adrp    x2, __boot_tables_end
    bl      rk_aarch64_inval
    adrp    x1, __boot_tables_start
    adrp    x2, __boot_tables_end
2:  stp     xzr, xzr, [x1], #16
    cmp     x1, x2
    b.lo    2b

    // TTBR0: the identity map of the 1 GiB at the start of the image.
    adrp    x1, rk_boot_id_l0
    adrp    x2, rk_boot_id_l1
    ubfx    x3, x20, #39, #9
    orr     x4, x2, #3
    str     x4, [x1, x3, lsl #3]
    ldr     x5, ={identity}
    mov     x6, x20
    bl      rk_aarch64_map_gib

    // TTBR1 entry 0: the direct map. The boot path maps only the blocks that hold the image and
    // the device tree. `paging::init` maps all RAM later. The device tree can be 2 MiB long.
    adrp    x1, rk_boot_k_l0
    adrp    x2, rk_boot_dm_l1
    orr     x4, x2, #3
    str     x4, [x1]
    ldr     x5, ={direct}
    mov     x6, x20
    bl      rk_aarch64_map_gib
    adrp    x6, __kernel_end
    sub     x6, x6, #1
    bl      rk_aarch64_map_gib
    cbz     x19, 3f
    mov     x6, x19
    bl      rk_aarch64_map_gib
    add     x6, x19, #(1 << 21)
    sub     x6, x6, #1
    bl      rk_aarch64_map_gib

    // TTBR1 entry 1: the first 1 GiB of physical addresses as device memory.
    // TODO: map the devices that the device tree gives, and not a fixed block of QEMU virt.
3:  adrp    x2, rk_boot_mmio_l1
    orr     x4, x2, #3
    str     x4, [x1, #8]
    ldr     x4, ={device}
    str     x4, [x2]

    // TTBR1 entry 511: the kernel image. KERNEL_BASE is the first address of this entry, so the
    // level 1 and level 2 indexes start at 0 and the level 3 tables are one array.
    adrp    x2, rk_boot_img_l1
    orr     x4, x2, #3
    str     x4, [x1, #(511 * 8)]
    adrp    x3, rk_boot_img_l2
    orr     x4, x3, #3
    str     x4, [x2]
    adrp    x8, __kernel_end
    sub     x5, x8, x20
    sub     x5, x5, #1
    lsr     x5, x5, #21
    add     x5, x5, #1                  // the number of level 3 tables
    adrp    x6, rk_boot_img_l3
4:  orr     x4, x6, #3
    str     x4, [x3], #8
    add     x6, x6, #4096
    subs    x5, x5, #1
    b.ne    4b
    adrp    x1, rk_boot_img_l3
    adrp    x6, __text_end
    adrp    x7, __rodata_end
    ldr     x9, ={rx}
    ldr     x10, ={ro}
    ldr     x11, ={rw}
    mov     x2, x20
5:  mov     x3, x11
    cmp     x2, x7
    csel    x3, x10, x3, lo
    cmp     x2, x6
    csel    x3, x9, x3, lo
    orr     x3, x3, x2
    str     x3, [x1], #8
    add     x2, x2, #4096
    cmp     x2, x8
    b.lo    5b

    adrp    x1, __boot_tables_start
    adrp    x2, __boot_tables_end
    bl      rk_aarch64_inval

    // Turn the MMU on. IPS comes from the physical address size of the CPU, at most 48 bits.
    ldr     x1, ={mair}
    msr     mair_el1, x1
    ldr     x1, ={tcr}
    mrs     x2, id_aa64mmfr0_el1
    and     x2, x2, #7
    cmp     x2, #5
    mov     x3, #5
    csel    x2, x3, x2, hi
    bfi     x1, x2, #32, #3
    msr     tcr_el1, x1
    adrp    x1, rk_boot_id_l0
    msr     ttbr0_el1, x1
    adrp    x1, rk_boot_k_l0
    msr     ttbr1_el1, x1
    isb
    tlbi    vmalle1
    dsb     nsh
    isb
    ldr     x1, ={sctlr_on}
    msr     sctlr_el1, x1
    isb
    ic      iallu
    dsb     nsh
    isb
    ldr     x1, =rk_aarch64_high
    br      x1

rk_aarch64_high:
    mrs     x1, tcr_el1
    orr     x1, x1, #{epd0}
    msr     tcr_el1, x1
    isb
    tlbi    vmalle1
    dsb     nsh
    isb
    msr     spsel, #1
    adrp    x1, rk_boot_stack_top
    add     x1, x1, :lo12:rk_boot_stack_top
    mov     sp, x1
    adrp    x1, __bss_start
    add     x1, x1, :lo12:__bss_start
    adrp    x2, __bss_end
    add     x2, x2, :lo12:__bss_end
6:  cmp     x1, x2
    b.hs    7f
    stp     xzr, xzr, [x1], #16
    b       6b
7:  adrp    x1, rk_aarch64_vectors
    add     x1, x1, :lo12:rk_aarch64_vectors
    msr     vbar_el1, x1
    isb
    mov     x0, x19
    mov     x1, x20
    mov     x29, xzr
    mov     x30, xzr
    bl      rk_frame_aarch64_entry
8:  wfi
    b       8b

    // The entry of the other CPUs, from PSCI `CPU_ON`, with the MMU off and the number of the CPU
    // in x0. The boot page tables are in place, so the CPU turns the MMU on with them as the boot
    // CPU did, and calls `rk_frame_aarch64_secondary_entry` on the stack in `rk_ap_stacks`.
    .global rk_aarch64_secondary
rk_aarch64_secondary:
    mov     x19, x0
    mrs     x1, CurrentEL
    cmp     x1, #(2 << 2)
    b.ne    1f
    mov     x1, #(1 << 31)
    msr     hcr_el2, x1
    mrs     x1, cnthctl_el2
    orr     x1, x1, #3
    msr     cnthctl_el2, x1
    msr     cntvoff_el2, xzr
    mov     x1, #0x33ff
    msr     cptr_el2, x1
    msr     hstr_el2, xzr
    ldr     x1, ={sctlr_off}
    msr     sctlr_el1, x1
    mov     x1, #0x3c5
    msr     spsr_el2, x1
    adr     x1, 1f
    msr     elr_el2, x1
    eret
1:  ldr     x1, ={sctlr_off}
    msr     sctlr_el1, x1
    isb
    mov     x1, #(3 << 20)
    msr     cpacr_el1, x1
    isb
    ldr     x1, ={mair}
    msr     mair_el1, x1
    ldr     x1, ={tcr}
    mrs     x2, id_aa64mmfr0_el1
    and     x2, x2, #7
    cmp     x2, #5
    mov     x3, #5
    csel    x2, x3, x2, hi
    bfi     x1, x2, #32, #3
    msr     tcr_el1, x1
    adrp    x1, rk_boot_id_l0
    msr     ttbr0_el1, x1
    adrp    x1, rk_boot_k_l0
    msr     ttbr1_el1, x1
    isb
    tlbi    vmalle1
    dsb     nsh
    isb
    ldr     x1, ={sctlr_on}
    msr     sctlr_el1, x1
    isb
    ic      iallu
    dsb     nsh
    isb
    ldr     x1, =rk_aarch64_secondary_high
    br      x1

rk_aarch64_secondary_high:
    mrs     x1, tcr_el1
    orr     x1, x1, #{epd0}
    msr     tcr_el1, x1
    isb
    tlbi    vmalle1
    dsb     nsh
    isb
    msr     spsel, #1
    adrp    x1, rk_ap_stacks
    add     x1, x1, :lo12:rk_ap_stacks
    ldr     x1, [x1, x19, lsl #3]
    mov     sp, x1
    adrp    x1, rk_aarch64_vectors
    add     x1, x1, :lo12:rk_aarch64_vectors
    msr     vbar_el1, x1
    isb
    mov     x0, x19
    mov     x29, xzr
    mov     x30, xzr
    bl      rk_frame_aarch64_secondary_entry
2:  wfi
    b       2b

    // Puts a 1 GiB block for the physical address x6 in the level 1 table x2, with the
    // attributes x5. The index is bits 38 to 30, so the address must be below 512 GiB.
rk_aarch64_map_gib:
    ubfx    x3, x6, #30, #9
    lsr     x4, x6, #30
    lsl     x4, x4, #30
    orr     x4, x4, x5
    str     x4, [x2, x3, lsl #3]
    ret

    // Invalidates the data cache lines from x1 to x2.
rk_aarch64_inval:
    mrs     x3, ctr_el0
    ubfx    x3, x3, #16, #4
    mov     x4, #4
    lsl     x4, x4, x3                  // the line size in bytes
    sub     x5, x4, #1
    bic     x1, x1, x5
9:  dc      ivac, x1
    add     x1, x1, x4
    cmp     x1, x2
    b.lo    9b
    dsb     sy
    ret

    .ltorg

    .section .boot.tables, "aw", %nobits
    .balign 4096
rk_boot_id_l0:
    .space  4096
rk_boot_id_l1:
    .space  4096
    .global rk_boot_k_l0
rk_boot_k_l0:
    .space  4096
rk_boot_dm_l1:
    .space  4096
rk_boot_mmio_l1:
    .space  4096
rk_boot_img_l1:
    .space  4096
rk_boot_img_l2:
    .space  4096
rk_boot_img_l3:
    .space  {l3_bytes}

    .section .boot.stack, "aw", %nobits
    .balign 16
rk_boot_stack:
    .space  {stack}
rk_boot_stack_top:
"#,
    flags = const IMAGE_FLAGS,
    sctlr_off = const paging::SCTLR_MMU_OFF,
    sctlr_on = const paging::SCTLR_MMU_ON,
    identity = const paging::BLOCK_IDENTITY,
    direct = const paging::BLOCK_DIRECT,
    device = const paging::BLOCK_DEVICE,
    rx = const paging::PTE_KERNEL_RX,
    ro = const paging::PTE_KERNEL_RO,
    rw = const paging::PTE_KERNEL_RW,
    mair = const paging::MAIR,
    tcr = const paging::TCR,
    epd0 = const paging::TCR_EPD0,
    l3_bytes = const IMAGE_L3_TABLES * 4096,
    stack = const BOOT_STACK_SIZE,
);

/// The first Rust code. The assembly above calls it at `KERNEL_BASE` on the boot stack, with the
/// physical addresses of the device tree and of the image.
#[unsafe(no_mangle)]
extern "C" fn rk_frame_aarch64_entry(dtb: u64, image: u64) -> ! {
    super::cpu::init(0);
    paging::set_kernel_phys(image);
    let mut info = BootInfo::new("linux");
    let platform = match read_device_tree(dtb, &mut info) {
        Ok(p) => p,
        Err(e) => panic!("the device tree at {dtb:#x} is not correct: {e}"),
    };
    super::set_psci_smc(platform.psci_smc);
    crate::mm::frame::init(&info, paging::kernel_phys());
    paging::init(&info);
    paging::init_cpu();
    use_devices(&platform, &info);
    super::smp::set_cpus(&platform.cpus[..platform.cpu_count]);
    super::gic::init();
    super::timer::init();
    super::user::init_cpu();
    crate::boot::start(info)
}

/// Points the drivers at the devices of the device tree. A device that the device tree does not
/// give, or that the kernel cannot map, stays at the address of QEMU `virt`.
fn use_devices(platform: &crate::fdt::Platform, info: &BootInfo) {
    let map = |phys: u64, len: u64| {
        let virt = paging::map_device(phys, len, info);
        if virt.is_none() {
            crate::println!("aarch64: cannot map the device at {phys:#x}");
        }
        virt
    };
    if let Some(base) = platform.uart.and_then(|p| map(p, 0x1000)) {
        super::pl011::set_base(base);
    }
    if let Some((d, r, len)) = platform.gic_v3 {
        match (map(d, 0x1_0000), map(r, len), usize::try_from(len)) {
            (Some(d), Some(r), Ok(len)) => super::gic::set_base_v3(d, r, len),
            _ => crate::println!("aarch64: cannot use the GICv3"),
        }
    } else if let Some((d, c)) = platform.gic
        && let (Some(d), Some(c)) = (map(d, 0x1000), map(c, 0x2000))
    {
        super::gic::set_base(d, c);
    }
    if let Some(intid) = platform.timer_intid {
        super::timer::set_intid(intid);
    }
    if let Some(base) = platform.rtc.and_then(|p| map(p, 0x1000)) {
        super::rtc::set_base(base);
    }
    crate::iomem::virtio_mmio::set(&platform.virtio_mmio[..platform.virtio_mmio_count]);
    // The scan of the PCI bus comes later, at the first `pci::devices`. It assigns the BARs,
    // because no firmware assigns them before `-kernel`.
    if let Some((ecam, len)) = platform.pci_ecam {
        match (map(ecam, len), usize::try_from(len)) {
            (Some(virt), Ok(len)) => crate::pci::set_host(platform, virt, len),
            _ => crate::println!("aarch64: cannot use the PCI ECAM at {ecam:#x}"),
        }
    }
}

/// Reads the device tree through the boot direct map, which maps the 2 MiB after its start.
fn read_device_tree(dtb: u64, info: &mut BootInfo) -> Result<crate::fdt::Platform, &'static str> {
    if dtb == 0 || !dtb.is_multiple_of(8) {
        return Err("no device tree");
    }
    let virt = paging::phys_to_virt(dtb) as *const u32;
    // SAFETY: the boot assembly maps the 2 MiB after `dtb` in the direct map, and the address is
    // aligned. The second word of the header is the size of the device tree.
    let size = u32::from_be(unsafe { virt.wrapping_add(1).read() }) as usize;
    if size > crate::fdt::MAX_SIZE {
        return Err("the device tree is larger than 2 MiB");
    }
    // SAFETY: as above, and `size` is at most 2 MiB. The memory is the device tree that the loader
    // gave, and no code writes it.
    let bytes = unsafe { core::slice::from_raw_parts(virt.cast::<u8>(), size) };
    crate::fdt::read(bytes, dtb, info)
}
