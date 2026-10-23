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
        KEEP(*(.boot.head))
        KEEP(*(.boot.text))
        . = ALIGN(4096);
        KEEP(*(.boot.data))
    } :boot

    .note.Xen : {
        KEEP(*(.note.Xen))
    } :boot :note

    . = ALIGN(4096) + KERNEL_BASE;
    __kernel_start = .;

    __text_start = .;
    .text : AT(ADDR(.text) - KERNEL_BASE) {
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

    .bss : AT(ADDR(.bss) - KERNEL_BASE) {
        . = ALIGN(16);
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        . = ALIGN(16);
        __bss_end = .;
    } :data

    . = ALIGN(4096);
    __kernel_end = .;

    /* The boot code clears the bss before paging is on, so it needs the physical addresses. */
    __bss_start_phys = __bss_start - KERNEL_BASE;
    __bss_end_phys = __bss_end - KERNEL_BASE;

    /DISCARD/ : {
        *(.eh_frame .eh_frame_hdr .comment .note.GNU-stack)
    }
}
