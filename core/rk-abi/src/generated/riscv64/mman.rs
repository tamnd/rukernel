// rk-abigen generated this file from Linux 7.3, from <linux/mman.h>.
// Do not edit it. Change rk-abigen and run it again.

//! The flags of `mmap`, `mprotect`, `mremap`, `msync`, `mlock` and `madvise`.

/// No further special treatment.
pub const MADV_NORMAL: u32 = 0;
/// `MAP_FILE` from `<linux/mman.h>`.
pub const MAP_FILE: u32 = 0;
/// `PKEY_UNRESTRICTED` from `<linux/mman.h>`.
pub const PKEY_UNRESTRICTED: u32 = 0;
/// Page can not be accessed.
pub const PROT_NONE: u32 = 0;
/// Expect random page references.
pub const MADV_RANDOM: u32 = 1;
/// Share changes.
pub const MAP_SHARED: u32 = 1;
/// Lock all current mappings.
pub const MCL_CURRENT: u32 = 1;
/// Lock pages in range after they are faulted in, do not prefault.
pub const MLOCK_ONFAULT: u32 = 1;
/// `MREMAP_MAYMOVE` from `<linux/mman.h>`.
pub const MREMAP_MAYMOVE: u32 = 1;
/// Sync memory asynchronously.
pub const MS_ASYNC: u32 = 1;
/// `PKEY_DISABLE_ACCESS` from `<linux/mman.h>`.
pub const PKEY_DISABLE_ACCESS: u32 = 1;
/// Page can be read.
pub const PROT_READ: u32 = 1;
/// Expect sequential page references.
pub const MADV_SEQUENTIAL: u32 = 2;
/// Changes are private.
pub const MAP_PRIVATE: u32 = 2;
/// Lock all future mappings.
pub const MCL_FUTURE: u32 = 2;
/// `MREMAP_FIXED` from `<linux/mman.h>`.
pub const MREMAP_FIXED: u32 = 2;
/// Invalidate the caches.
pub const MS_INVALIDATE: u32 = 2;
/// `PKEY_DISABLE_WRITE` from `<linux/mman.h>`.
pub const PKEY_DISABLE_WRITE: u32 = 2;
/// Page can be written.
pub const PROT_WRITE: u32 = 2;
/// Will need these pages.
pub const MADV_WILLNEED: u32 = 3;
/// Share + validate extension flags.
pub const MAP_SHARED_VALIDATE: u32 = 3;
/// `PKEY_ACCESS_MASK` from `<linux/mman.h>`.
pub const PKEY_ACCESS_MASK: u32 = 3;
/// Don't need these pages.
pub const MADV_DONTNEED: u32 = 4;
/// Lock all pages that are faulted in.
pub const MCL_ONFAULT: u32 = 4;
/// `MREMAP_DONTUNMAP` from `<linux/mman.h>`.
pub const MREMAP_DONTUNMAP: u32 = 4;
/// Synchronous memory sync.
pub const MS_SYNC: u32 = 4;
/// Page can be executed.
pub const PROT_EXEC: u32 = 4;
/// Free pages only if memory pressure.
pub const MADV_FREE: u32 = 8;
/// Zero memory under memory pressure.
pub const MAP_DROPPABLE: u32 = 8;
/// Page may be used for atomic ops.
pub const PROT_SEM: u32 = 8;
/// Remove these pages & resources.
pub const MADV_REMOVE: u32 = 9;
/// Don't inherit across fork.
pub const MADV_DONTFORK: u32 = 10;
/// Do inherit across fork.
pub const MADV_DOFORK: u32 = 11;
/// KSM may merge identical pages.
pub const MADV_MERGEABLE: u32 = 12;
/// KSM may not merge identical pages.
pub const MADV_UNMERGEABLE: u32 = 13;
/// Worth backing with hugepages.
pub const MADV_HUGEPAGE: u32 = 14;
/// Not worth backing with hugepages.
pub const MADV_NOHUGEPAGE: u32 = 15;
/// Mask for type of mapping.
pub const MAP_TYPE: u32 = 15;
/// `MADV_DONTDUMP` from `<linux/mman.h>`.
pub const MADV_DONTDUMP: u32 = 16;
/// Interpret addr exactly.
pub const MAP_FIXED: u32 = 16;
/// Clear the MADV\_DONTDUMP flag.
pub const MADV_DODUMP: u32 = 17;
/// Zero memory on fork, child only.
pub const MADV_WIPEONFORK: u32 = 18;
/// Undo MADV\_WIPEONFORK.
pub const MADV_KEEPONFORK: u32 = 19;
/// Deactivate these pages.
pub const MADV_COLD: u32 = 20;
/// Reclaim these pages.
pub const MADV_PAGEOUT: u32 = 21;
/// Populate (prefault) page tables readable.
pub const MADV_POPULATE_READ: u32 = 22;
/// Populate (prefault) page tables writable.
pub const MADV_POPULATE_WRITE: u32 = 23;
/// Like DONTNEED, but drop locked pages too.
pub const MADV_DONTNEED_LOCKED: u32 = 24;
/// Synchronous hugepage collapse.
pub const MADV_COLLAPSE: u32 = 25;
/// `MAP_HUGE_SHIFT` from `<linux/mman.h>`.
pub const MAP_HUGE_SHIFT: u32 = 26;
/// Don't use a file.
pub const MAP_ANONYMOUS: u32 = 32;
/// `MAP_HUGE_MASK` from `<linux/mman.h>`.
pub const MAP_HUGE_MASK: u32 = 63;
/// Poison a page for testing.
pub const MADV_HWPOISON: u32 = 100;
/// Soft offline page for testing.
pub const MADV_SOFT_OFFLINE: u32 = 101;
/// Fatal signal on access to range.
pub const MADV_GUARD_INSTALL: u32 = 102;
/// Unguard range.
pub const MADV_GUARD_REMOVE: u32 = 103;
/// Stack-like segment.
pub const MAP_GROWSDOWN: u32 = 0x100;
/// ETXTBSY.
pub const MAP_DENYWRITE: u32 = 0x800;
/// Mark it as an executable.
pub const MAP_EXECUTABLE: u32 = 0x1000;
/// Pages are locked.
pub const MAP_LOCKED: u32 = 0x2000;
/// Don't check for reservations.
pub const MAP_NORESERVE: u32 = 0x4000;
/// Populate (prefault) pagetables.
pub const MAP_POPULATE: u32 = 0x8000;
/// Do not block on IO.
pub const MAP_NONBLOCK: u32 = 0x1_0000;
/// Give out an address that is best suited for process/thread stacks.
pub const MAP_STACK: u32 = 0x2_0000;
/// Create a huge page mapping.
pub const MAP_HUGETLB: u32 = 0x4_0000;
/// Perform synchronous page faults for the mapping.
pub const MAP_SYNC: u32 = 0x8_0000;
/// MAP\_FIXED which doesn't unmap underlying mapping.
pub const MAP_FIXED_NOREPLACE: u32 = 0x10_0000;
/// Mprotect flag: extend change to start of growsdown vma.
pub const PROT_GROWSDOWN: u32 = 0x100_0000;
/// Mprotect flag: extend change to end of growsup vma.
pub const PROT_GROWSUP: u32 = 0x200_0000;
/// `MAP_UNINITIALIZED` from `<linux/mman.h>`.
pub const MAP_UNINITIALIZED: u32 = 0x400_0000;
/// `MAP_HUGE_16KB` from `<linux/mman.h>`.
pub const MAP_HUGE_16KB: u32 = 0x3800_0000;
/// `MAP_HUGE_64KB` from `<linux/mman.h>`.
pub const MAP_HUGE_64KB: u32 = 0x4000_0000;
/// `MAP_HUGE_512KB` from `<linux/mman.h>`.
pub const MAP_HUGE_512KB: u32 = 0x4c00_0000;
/// `MAP_HUGE_1MB` from `<linux/mman.h>`.
pub const MAP_HUGE_1MB: u32 = 0x5000_0000;
/// `MAP_HUGE_2MB` from `<linux/mman.h>`.
pub const MAP_HUGE_2MB: u32 = 0x5400_0000;
/// `MAP_HUGE_8MB` from `<linux/mman.h>`.
pub const MAP_HUGE_8MB: u32 = 0x5c00_0000;
/// `MAP_HUGE_16MB` from `<linux/mman.h>`.
pub const MAP_HUGE_16MB: u32 = 0x6000_0000;
/// `MAP_HUGE_32MB` from `<linux/mman.h>`.
pub const MAP_HUGE_32MB: u32 = 0x6400_0000;
/// `MAP_HUGE_256MB` from `<linux/mman.h>`.
pub const MAP_HUGE_256MB: u32 = 0x7000_0000;
/// `MAP_HUGE_512MB` from `<linux/mman.h>`.
pub const MAP_HUGE_512MB: u32 = 0x7400_0000;
/// `MAP_HUGE_1GB` from `<linux/mman.h>`.
pub const MAP_HUGE_1GB: u32 = 0x7800_0000;
/// `MAP_HUGE_2GB` from `<linux/mman.h>`.
pub const MAP_HUGE_2GB: u32 = 0x7c00_0000;
/// `MAP_HUGE_16GB` from `<linux/mman.h>`.
pub const MAP_HUGE_16GB: u32 = 0x8800_0000;
