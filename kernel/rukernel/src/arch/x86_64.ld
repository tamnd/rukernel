/*
 * The memory layout of the x86-64 kernel image.
 *
 * The boot code and the boot page tables are at physical address 1 MiB, and they run there before
 * paging is on. The rest of the kernel runs at the kernel base 0xffffffff80000000, which the boot
 * page tables map to physical address 0. The loader puts each segment at its physical address.
 */

ENTRY(rk_pvh_start32)

KERNEL_BASE = 0xffffffff80000000;

PHDRS
{
    boot   PT_LOAD FLAGS(7);
    text   PT_LOAD FLAGS(5);
    rodata PT_LOAD FLAGS(4);
    data   PT_LOAD FLAGS(6);
    note   PT_NOTE FLAGS(4);
}

SECTIONS
{
    . = 0x100000;

    .boot : {
        KEEP(*(.boot.text))
        . = ALIGN(4096);
        KEEP(*(.boot.data))
    } :boot

    .note.Xen : {
        KEEP(*(.note.Xen))
    } :boot :note

    . = ALIGN(4096) + KERNEL_BASE;
    __kernel_start = .;

    .text : AT(ADDR(.text) - KERNEL_BASE) {
        *(.text .text.*)
    } :text

    . = ALIGN(4096);
    .rodata : AT(ADDR(.rodata) - KERNEL_BASE) {
        *(.rodata .rodata.*)
    } :rodata

    . = ALIGN(4096);
    .data : AT(ADDR(.data) - KERNEL_BASE) {
        *(.data .data.*)
    } :data

    .bss : AT(ADDR(.bss) - KERNEL_BASE) {
        *(.bss .bss.*)
        *(COMMON)
    } :data

    . = ALIGN(4096);
    __kernel_end = .;

    /DISCARD/ : {
        *(.eh_frame .eh_frame_hdr .comment .note.GNU-stack)
    }
}
