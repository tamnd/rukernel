/*
 * The memory layout of the arm64 kernel image.
 *
 * The image is a Linux arm64 Image. The loader puts the file at a 2 MiB aligned physical address
 * and starts the CPU at its first byte, which is the image header in .head.text. The kernel is
 * linked at the kernel base 0xffffff8000000000, which is the start of the last level 0 entry of
 * TTBR1. The boot code maps the image there from the physical address where the loader put it. The
 * physical addresses of the segments start at 0, so the build makes the Image file from the
 * segments at their physical addresses. The boot page tables and the boot stack come after the
 * bss. They have no bytes in the file, but the image size in the header includes them.
 */

ENTRY(_head)

KERNEL_BASE = 0xffffff8000000000;

PHDRS
{
    text   PT_LOAD FLAGS(5);
    rodata PT_LOAD FLAGS(4);
    data   PT_LOAD FLAGS(6);
}

SECTIONS
{
    . = KERNEL_BASE;
    __kernel_start = .;

    __text_start = .;
    .text : AT(ADDR(.text) - KERNEL_BASE) {
        KEEP(*(.head.text))
        *(.text .text.*)
    } :text

    . = ALIGN(4096);
    __text_end = .;
    __rodata_start = .;
    .rodata : AT(ADDR(.rodata) - KERNEL_BASE) {
        *(.rodata .rodata.*)
        /* The exception table: pairs of a faulting instruction and its fixup address. */
        . = ALIGN(16);
        __start___ex_table = .;
        KEEP(*(__ex_table))
        __stop___ex_table = .;
    } :rodata

    . = ALIGN(4096);
    __rodata_end = .;
    __data_start = .;
    .data : AT(ADDR(.data) - KERNEL_BASE) {
        *(.data .data.*)
        *(.got .got.*)
    } :data

    .bss (NOLOAD) : AT(ADDR(.bss) - KERNEL_BASE) {
        . = ALIGN(16);
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        . = ALIGN(16);
        __bss_end = .;
    } :data

    /* The boot code clears these tables before it uses them, so the bss clear does not need to. */
    .boot.tables (NOLOAD) : AT(ADDR(.boot.tables) - KERNEL_BASE) {
        . = ALIGN(4096);
        __boot_tables_start = .;
        KEEP(*(.boot.tables))
        . = ALIGN(4096);
        __boot_tables_end = .;
    } :data

    .boot.stack (NOLOAD) : AT(ADDR(.boot.stack) - KERNEL_BASE) {
        KEEP(*(.boot.stack))
    } :data

    . = ALIGN(4096);
    __kernel_end = .;
    __image_size = __kernel_end - __kernel_start;

    /* The boot code has 32 level 3 tables for the image, and each maps 2 MiB. */
    ASSERT(__image_size <= 32 * 2 * 1024 * 1024, "the kernel image is larger than 64 MiB")

    /DISCARD/ : {
        *(.eh_frame .eh_frame_hdr .comment .note.GNU-stack)
    }
}
