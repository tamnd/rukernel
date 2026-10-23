// rk-abigen generated this file from Linux 7.3, from <linux/auxvec.h>.
// Do not edit it. Change rk-abigen and run it again.

//! The types of the entries of the auxiliary vector.

/// End of vector.
pub const AT_NULL: u32 = 0;
/// Entry should be ignored.
pub const AT_IGNORE: u32 = 1;
/// File descriptor of program.
pub const AT_EXECFD: u32 = 2;
/// Program headers for program.
pub const AT_PHDR: u32 = 3;
/// Size of program header entry.
pub const AT_PHENT: u32 = 4;
/// Number of program headers.
pub const AT_PHNUM: u32 = 5;
/// System page size.
pub const AT_PAGESZ: u32 = 6;
/// Base address of interpreter.
pub const AT_BASE: u32 = 7;
/// Flags.
pub const AT_FLAGS: u32 = 8;
/// Entry point of program.
pub const AT_ENTRY: u32 = 9;
/// Program is not ELF.
pub const AT_NOTELF: u32 = 10;
/// `AT_VECTOR_SIZE_ARCH` from `<linux/auxvec.h>`.
pub const AT_VECTOR_SIZE_ARCH: u32 = 10;
/// Real uid.
pub const AT_UID: u32 = 11;
/// Effective uid.
pub const AT_EUID: u32 = 12;
/// Real gid.
pub const AT_GID: u32 = 13;
/// Effective gid.
pub const AT_EGID: u32 = 14;
/// String identifying CPU for optimizations.
pub const AT_PLATFORM: u32 = 15;
/// Arch dependent hints at CPU capabilities.
pub const AT_HWCAP: u32 = 16;
/// Frequency at which times() increments.
pub const AT_CLKTCK: u32 = 17;
/// Secure mode boolean.
pub const AT_SECURE: u32 = 23;
/// `AT_BASE_PLATFORM` from `<linux/auxvec.h>`.
pub const AT_BASE_PLATFORM: u32 = 24;
/// Address of 16 random bytes.
pub const AT_RANDOM: u32 = 25;
/// Extension of AT\_HWCAP.
pub const AT_HWCAP2: u32 = 26;
/// Rseq supported feature size.
pub const AT_RSEQ_FEATURE_SIZE: u32 = 27;
/// Rseq allocation alignment.
pub const AT_RSEQ_ALIGN: u32 = 28;
/// Extension of AT\_HWCAP.
pub const AT_HWCAP3: u32 = 29;
/// Extension of AT\_HWCAP.
pub const AT_HWCAP4: u32 = 30;
/// Filename of program.
pub const AT_EXECFN: u32 = 31;
/// `AT_SYSINFO_EHDR` from `<linux/auxvec.h>`.
pub const AT_SYSINFO_EHDR: u32 = 33;
/// `AT_L1I_CACHESIZE` from `<linux/auxvec.h>`.
pub const AT_L1I_CACHESIZE: u32 = 40;
/// `AT_L1I_CACHEGEOMETRY` from `<linux/auxvec.h>`.
pub const AT_L1I_CACHEGEOMETRY: u32 = 41;
/// `AT_L1D_CACHESIZE` from `<linux/auxvec.h>`.
pub const AT_L1D_CACHESIZE: u32 = 42;
/// `AT_L1D_CACHEGEOMETRY` from `<linux/auxvec.h>`.
pub const AT_L1D_CACHEGEOMETRY: u32 = 43;
/// `AT_L2_CACHESIZE` from `<linux/auxvec.h>`.
pub const AT_L2_CACHESIZE: u32 = 44;
/// `AT_L2_CACHEGEOMETRY` from `<linux/auxvec.h>`.
pub const AT_L2_CACHEGEOMETRY: u32 = 45;
/// `AT_L3_CACHESIZE` from `<linux/auxvec.h>`.
pub const AT_L3_CACHESIZE: u32 = 46;
/// `AT_L3_CACHEGEOMETRY` from `<linux/auxvec.h>`.
pub const AT_L3_CACHEGEOMETRY: u32 = 47;
/// Minimal stack size for signal delivery.
pub const AT_MINSIGSTKSZ: u32 = 51;
