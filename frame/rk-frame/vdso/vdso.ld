/* The layout of the vDSO, as in arch/x86/entry/vdso/vdso-layout.lds.S of Linux. All of the vDSO
 * is in one page aligned segment that can be read and run. The data page is the page below it.
 * The file `x86_64.ver` or `aarch64.ver` gives the symbols and their version. */

SECTIONS
{
    . = SIZEOF_HEADERS;

    .hash           : { *(.hash) }                  :text
    .gnu.hash       : { *(.gnu.hash) }
    .dynsym         : { *(.dynsym) }
    .dynstr         : { *(.dynstr) }
    .gnu.version    : { *(.gnu.version) }
    .gnu.version_d  : { *(.gnu.version_d) }
    .gnu.version_r  : { *(.gnu.version_r) }
    .dynamic        : { *(.dynamic) }               :text :dynamic
    .rodata         : { *(.rodata*) }               :text
    .note           : { *(.note.*) }                :text
    .eh_frame_hdr   : { *(.eh_frame_hdr) }          :text :eh_frame_hdr
    .eh_frame       : { KEEP (*(.eh_frame)) }       :text
    .text           : { *(.text*) }                 :text

    /DISCARD/ : { *(.comment) *(.note.GNU-stack) }
}

PHDRS
{
    text            PT_LOAD         FLAGS(5) FILEHDR PHDRS;
    dynamic         PT_DYNAMIC      FLAGS(4);
    eh_frame_hdr    PT_GNU_EH_FRAME;
}
