// rk-abigen generated this file from Linux 7.3, from <linux/elf.h>.
// Do not edit it. Change rk-abigen and run it again.

//! The values of the ELF header and the program header.

/// E\_ident\[\] indexes.
pub const EI_MAG0: u32 = 0;
/// EI\_CLASS.
pub const ELFCLASSNONE: u32 = 0;
/// E\_ident\[EI\_DATA\].
pub const ELFDATANONE: u32 = 0;
/// `ELFOSABI_NONE` from `<linux/elf.h>`.
pub const ELFOSABI_NONE: u32 = 0;
/// `EM_NONE` from `<linux/elf.h>`.
pub const EM_NONE: u32 = 0;
/// `ET_NONE` from `<linux/elf.h>`.
pub const ET_NONE: u32 = 0;
/// E\_version, EI\_VERSION.
pub const EV_NONE: u32 = 0;
/// `PT_NULL` from `<linux/elf.h>`.
pub const PT_NULL: u32 = 0;
/// `EI_MAG1` from `<linux/elf.h>`.
pub const EI_MAG1: u32 = 1;
/// `ELFCLASS32` from `<linux/elf.h>`.
pub const ELFCLASS32: u32 = 1;
/// `ELFDATA2LSB` from `<linux/elf.h>`.
pub const ELFDATA2LSB: u32 = 1;
/// `EM_M32` from `<linux/elf.h>`.
pub const EM_M32: u32 = 1;
/// `ET_REL` from `<linux/elf.h>`.
pub const ET_REL: u32 = 1;
/// `EV_CURRENT` from `<linux/elf.h>`.
pub const EV_CURRENT: u32 = 1;
/// `PF_X` from `<linux/elf.h>`.
pub const PF_X: u32 = 1;
/// `PT_LOAD` from `<linux/elf.h>`.
pub const PT_LOAD: u32 = 1;
/// `EI_MAG2` from `<linux/elf.h>`.
pub const EI_MAG2: u32 = 2;
/// `ELFCLASS64` from `<linux/elf.h>`.
pub const ELFCLASS64: u32 = 2;
/// `ELFDATA2MSB` from `<linux/elf.h>`.
pub const ELFDATA2MSB: u32 = 2;
/// `EM_SPARC` from `<linux/elf.h>`.
pub const EM_SPARC: u32 = 2;
/// `ET_EXEC` from `<linux/elf.h>`.
pub const ET_EXEC: u32 = 2;
/// `EV_NUM` from `<linux/elf.h>`.
pub const EV_NUM: u32 = 2;
/// `PF_W` from `<linux/elf.h>`.
pub const PF_W: u32 = 2;
/// `PT_DYNAMIC` from `<linux/elf.h>`.
pub const PT_DYNAMIC: u32 = 2;
/// `EI_MAG3` from `<linux/elf.h>`.
pub const EI_MAG3: u32 = 3;
/// `ELFCLASSNUM` from `<linux/elf.h>`.
pub const ELFCLASSNUM: u32 = 3;
/// `ELFOSABI_LINUX` from `<linux/elf.h>`.
pub const ELFOSABI_LINUX: u32 = 3;
/// `EM_386` from `<linux/elf.h>`.
pub const EM_386: u32 = 3;
/// `ET_DYN` from `<linux/elf.h>`.
pub const ET_DYN: u32 = 3;
/// `PT_INTERP` from `<linux/elf.h>`.
pub const PT_INTERP: u32 = 3;
/// `EI_CLASS` from `<linux/elf.h>`.
pub const EI_CLASS: u32 = 4;
/// `EM_68K` from `<linux/elf.h>`.
pub const EM_68K: u32 = 4;
/// `ET_CORE` from `<linux/elf.h>`.
pub const ET_CORE: u32 = 4;
/// `PF_R` from `<linux/elf.h>`.
pub const PF_R: u32 = 4;
/// `PT_NOTE` from `<linux/elf.h>`.
pub const PT_NOTE: u32 = 4;
/// `EI_DATA` from `<linux/elf.h>`.
pub const EI_DATA: u32 = 5;
/// `EM_88K` from `<linux/elf.h>`.
pub const EM_88K: u32 = 5;
/// `PT_SHLIB` from `<linux/elf.h>`.
pub const PT_SHLIB: u32 = 5;
/// `EI_VERSION` from `<linux/elf.h>`.
pub const EI_VERSION: u32 = 6;
/// Perhaps disused.
pub const EM_486: u32 = 6;
/// `PT_PHDR` from `<linux/elf.h>`.
pub const PT_PHDR: u32 = 6;
/// `EI_OSABI` from `<linux/elf.h>`.
pub const EI_OSABI: u32 = 7;
/// `EM_860` from `<linux/elf.h>`.
pub const EM_860: u32 = 7;
/// Thread local storage segment.
pub const PT_TLS: u32 = 7;
/// `EI_PAD` from `<linux/elf.h>`.
pub const EI_PAD: u32 = 8;
/// MIPS R3000 (officially, big-endian only).
pub const EM_MIPS: u32 = 8;
/// MIPS R3000 little-endian.
pub const EM_MIPS_RS3_LE: u32 = 10;
/// MIPS R4000 big-endian.
pub const EM_MIPS_RS4_BE: u32 = 10;
/// HPPA.
pub const EM_PARISC: u32 = 15;
/// `EI_NIDENT` from `<linux/elf.h>`.
pub const EI_NIDENT: u32 = 16;
/// Sun's "v8plus".
pub const EM_SPARC32PLUS: u32 = 18;
/// PowerPC.
pub const EM_PPC: u32 = 20;
/// PowerPC64.
pub const EM_PPC64: u32 = 21;
/// IBM S/390.
pub const EM_S390: u32 = 22;
/// Cell BE SPU.
pub const EM_SPU: u32 = 23;
/// ARM 32 bit.
pub const EM_ARM: u32 = 40;
/// SuperH.
pub const EM_SH: u32 = 42;
/// SPARC v9 64-bit.
pub const EM_SPARCV9: u32 = 43;
/// Renesas H8/300.
pub const EM_H8_300: u32 = 46;
/// HP/Intel IA-64.
pub const EM_IA_64: u32 = 50;
/// AMD x86-64.
pub const EM_X86_64: u32 = 62;
/// Axis Communications 32-bit embedded processor.
pub const EM_CRIS: u32 = 76;
/// Renesas M32R.
pub const EM_M32R: u32 = 88;
/// Panasonic/MEI MN10300, AM33.
pub const EM_MN10300: u32 = 89;
/// OpenRISC 32-bit embedded processor.
pub const EM_OPENRISC: u32 = 92;
/// ARCompact processor.
pub const EM_ARCOMPACT: u32 = 93;
/// Tensilica Xtensa Architecture.
pub const EM_XTENSA: u32 = 94;
/// ADI Blackfin Processor.
pub const EM_BLACKFIN: u32 = 106;
/// UniCore-32.
pub const EM_UNICORE: u32 = 110;
/// Altera Nios II soft-core processor.
pub const EM_ALTERA_NIOS2: u32 = 113;
/// TI C6X DSPs.
pub const EM_TI_C6000: u32 = 140;
/// QUALCOMM Hexagon.
pub const EM_HEXAGON: u32 = 164;
/// `EM_NDS32` from `<linux/elf.h>`.
pub const EM_NDS32: u32 = 167;
/// ARM 64 bit.
pub const EM_AARCH64: u32 = 183;
/// Tilera TILEPro.
pub const EM_TILEPRO: u32 = 188;
/// Xilinx MicroBlaze.
pub const EM_MICROBLAZE: u32 = 189;
/// Tilera TILE-Gx.
pub const EM_TILEGX: u32 = 191;
/// ARCv2 Cores.
pub const EM_ARCV2: u32 = 195;
/// RISC-V.
pub const EM_RISCV: u32 = 243;
/// Linux BPF - in-kernel virtual machine.
pub const EM_BPF: u32 = 247;
/// C-SKY.
pub const EM_CSKY: u32 = 252;
/// LoongArch.
pub const EM_LOONGARCH: u32 = 0x102;
/// Fujitsu FR-V.
pub const EM_FRV: u32 = 0x5441;
/// `EM_ALPHA` from `<linux/elf.h>`.
pub const EM_ALPHA: u32 = 0x9026;
/// `EM_CYGNUS_M32R` from `<linux/elf.h>`.
pub const EM_CYGNUS_M32R: u32 = 0x9041;
/// `EM_S390_OLD` from `<linux/elf.h>`.
pub const EM_S390_OLD: u32 = 0xa390;
/// `EM_CYGNUS_MN10300` from `<linux/elf.h>`.
pub const EM_CYGNUS_MN10300: u32 = 0xbeef;
/// `ET_LOPROC` from `<linux/elf.h>`.
pub const ET_LOPROC: u32 = 0xff00;
/// `ET_HIPROC` from `<linux/elf.h>`.
pub const ET_HIPROC: u32 = 0xffff;
/// OS-specific.
pub const PT_LOOS: u32 = 0x6000_0000;
/// `PT_GNU_EH_FRAME` from `<linux/elf.h>`.
pub const PT_GNU_EH_FRAME: u32 = 0x6474_e550;
/// `PT_GNU_STACK` from `<linux/elf.h>`.
pub const PT_GNU_STACK: u32 = 0x6474_e551;
/// `PT_GNU_RELRO` from `<linux/elf.h>`.
pub const PT_GNU_RELRO: u32 = 0x6474_e552;
/// `PT_GNU_PROPERTY` from `<linux/elf.h>`.
pub const PT_GNU_PROPERTY: u32 = 0x6474_e553;
/// OS-specific.
pub const PT_HIOS: u32 = 0x6fff_ffff;
/// `PT_LOPROC` from `<linux/elf.h>`.
pub const PT_LOPROC: u32 = 0x7000_0000;
/// `PT_AARCH64_MEMTAG_MTE` from `<linux/elf.h>`.
pub const PT_AARCH64_MEMTAG_MTE: u32 = 0x7000_0002;
/// `PT_HIPROC` from `<linux/elf.h>`.
pub const PT_HIPROC: u32 = 0x7fff_ffff;
