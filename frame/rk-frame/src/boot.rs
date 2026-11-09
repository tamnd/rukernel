//! What the boot loader tells the kernel.
//!
//! Each boot protocol fills a `BootInfo`: PVH now, and the Linux boot protocol and UEFI later in
//! R0, per spec/15-boot-and-platform.md section 15.3. The kernel sees one structure for all
//! protocols.

use crate::addr::PhysAddr;
use core::fmt;

/// The longest command line that the kernel keeps. Linux uses 2048 bytes on x86-64.
pub const COMMAND_LINE_SIZE: usize = 2048;

/// The largest number of memory map entries that the kernel keeps. The E820 table of Linux has
/// the same limit before it extends the table.
pub const MAX_REGIONS: usize = 128;

/// The kind of a physical memory range, with the E820 type names.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MemoryKind {
    /// Memory that the kernel can use.
    Usable,
    /// Memory that the firmware or a device uses.
    Reserved,
    /// ACPI tables. The kernel can use the memory after it reads the tables.
    AcpiReclaimable,
    /// ACPI non volatile storage. The kernel must keep it.
    AcpiNvs,
    /// Memory with errors.
    Unusable,
    /// Persistent memory.
    Persistent,
    /// A type that this kernel does not know.
    Other(u32),
}

impl MemoryKind {
    /// Converts an E820 type number.
    pub const fn from_e820(kind: u32) -> Self {
        match kind {
            1 => Self::Usable,
            2 => Self::Reserved,
            3 => Self::AcpiReclaimable,
            4 => Self::AcpiNvs,
            5 => Self::Unusable,
            7 => Self::Persistent,
            n => Self::Other(n),
        }
    }
}

impl fmt::Display for MemoryKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usable => f.write_str("usable"),
            Self::Reserved => f.write_str("reserved"),
            Self::AcpiReclaimable => f.write_str("ACPI data"),
            Self::AcpiNvs => f.write_str("ACPI NVS"),
            Self::Unusable => f.write_str("unusable"),
            Self::Persistent => f.write_str("persistent"),
            Self::Other(n) => write!(f, "type {n}"),
        }
    }
}

/// One range of physical memory.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MemoryRegion {
    /// The first address.
    pub start: PhysAddr,
    /// The length in bytes.
    pub len: u64,
    /// The kind of memory.
    pub kind: MemoryKind,
}

/// What the boot loader tells the kernel.
pub struct BootInfo {
    protocol: &'static str,
    cmdline: [u8; COMMAND_LINE_SIZE],
    cmdline_len: usize,
    regions: [MemoryRegion; MAX_REGIONS],
    region_count: usize,
    rsdp: Option<PhysAddr>,
    smbios: Option<PhysAddr>,
    initrd: Option<(PhysAddr, u64)>,
}

impl BootInfo {
    /// Makes an empty structure for a boot protocol.
    pub const fn new(protocol: &'static str) -> Self {
        const EMPTY: MemoryRegion =
            MemoryRegion { start: PhysAddr::new(0), len: 0, kind: MemoryKind::Reserved };
        Self {
            protocol,
            cmdline: [0; COMMAND_LINE_SIZE],
            cmdline_len: 0,
            regions: [EMPTY; MAX_REGIONS],
            region_count: 0,
            rsdp: None,
            smbios: None,
            initrd: None,
        }
    }

    /// The name of the boot protocol, for the boot log.
    pub fn protocol(&self) -> &'static str {
        self.protocol
    }

    /// The kernel command line. Bytes that are not UTF-8 end the command line.
    pub fn cmdline(&self) -> &str {
        let bytes = &self.cmdline[..self.cmdline_len];
        match core::str::from_utf8(bytes) {
            Ok(s) => s,
            Err(e) => core::str::from_utf8(&bytes[..e.valid_up_to()]).unwrap_or(""),
        }
    }

    /// The physical memory map, in the order that the boot loader gave it.
    pub fn memory(&self) -> &[MemoryRegion] {
        &self.regions[..self.region_count]
    }

    /// The physical address of the ACPI RSDP, if the boot loader gave it.
    pub fn rsdp(&self) -> Option<PhysAddr> {
        self.rsdp
    }

    /// The physical address of the SMBIOS entry point, if the EFI firmware gave it.
    pub fn smbios(&self) -> Option<PhysAddr> {
        self.smbios
    }

    /// The physical address and the length of the initramfs, if the boot loader gave one.
    pub fn initrd(&self) -> Option<(PhysAddr, u64)> {
        self.initrd
    }

    /// The bytes of the initramfs, if the boot loader gave one. The frame allocator reserves its
    /// frames, so the bytes stay the same for the life of the kernel.
    #[cfg(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64")))]
    pub fn initrd_bytes(&self) -> Option<&'static [u8]> {
        let (start, len) = self.initrd?;
        let len = usize::try_from(len).ok()?;
        let virt = crate::arch::imp::paging::phys_to_virt(start.get()) as *const u8;
        // SAFETY: `frame::init` reserves the frames of the initramfs, so no owner writes them, and
        // `paging::init` puts them in the direct map, which stays for the life of the kernel.
        Some(unsafe { core::slice::from_raw_parts(virt, len) })
    }

    /// The bytes of the initramfs. The other targets have no direct map yet, so they give `None`.
    #[cfg(not(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64"))))]
    pub fn initrd_bytes(&self) -> Option<&'static [u8]> {
        None
    }

    /// Adds a byte to the command line. Gives `false` when the command line is full.
    pub fn push_cmdline_byte(&mut self, b: u8) -> bool {
        if self.cmdline_len == COMMAND_LINE_SIZE - 1 {
            return false;
        }
        self.cmdline[self.cmdline_len] = b;
        self.cmdline_len += 1;
        true
    }

    /// Adds a memory map entry. An entry with length 0 is ignored. An entry that starts at the end
    /// of the last entry and has the same kind becomes part of the last entry. An EFI memory map
    /// has many such entries. When the table is full, the entry is ignored.
    pub fn push_region(&mut self, start: PhysAddr, len: u64, kind: MemoryKind) {
        if len == 0 {
            return;
        }
        if let Some(last) = self.region_count.checked_sub(1).map(|i| &mut self.regions[i])
            && last.kind == kind
            && last.start.get().checked_add(last.len) == Some(start.get())
        {
            last.len += len;
            return;
        }
        if self.region_count == MAX_REGIONS {
            return;
        }
        self.regions[self.region_count] = MemoryRegion { start, len, kind };
        self.region_count += 1;
    }

    /// Records the ACPI RSDP.
    pub fn set_rsdp(&mut self, rsdp: PhysAddr) {
        self.rsdp = Some(rsdp);
    }

    /// Records the SMBIOS entry point.
    pub fn set_smbios(&mut self, smbios: PhysAddr) {
        self.smbios = Some(smbios);
    }

    /// Records the initramfs.
    pub fn set_initrd(&mut self, start: PhysAddr, len: u64) {
        if len > 0 {
            self.initrd = Some((start, len));
        }
    }

    /// Records the initramfs of `initrdmem=ADDRESS,SIZE` on the command line, if the boot
    /// protocol gave no initramfs, as `early_initrdmem` of Linux. The boot loader or QEMU (with
    /// `-device loader`) put it in memory at the address. The numbers have the form of `memparse`:
    /// decimal or `0x` hexadecimal, with an optional `K`, `M` or `G`.
    pub fn initrd_from_cmdline(&mut self) {
        if self.initrd.is_some() {
            return;
        }
        let Some(arg) = self.cmdline().split(' ').find_map(|w| w.strip_prefix("initrdmem=")) else {
            return;
        };
        if let Some((start, len)) = arg.split_once(',')
            && let (Some(start), Some(len)) = (memparse(start), memparse(len))
            && start.checked_add(len).is_some()
        {
            self.set_initrd(PhysAddr::new(start), len);
        }
    }

    /// The number of bytes of usable memory in the map.
    pub fn usable_bytes(&self) -> u64 {
        self.memory().iter().filter(|r| r.kind == MemoryKind::Usable).map(|r| r.len).sum()
    }
}

/// Reads a number as `memparse` of Linux: decimal or `0x` hexadecimal, with an optional `K`,
/// `M` or `G`.
fn memparse(s: &str) -> Option<u64> {
    let (digits, shift) = match s.as_bytes().last()? {
        b'K' | b'k' => (&s[..s.len() - 1], 10),
        b'M' | b'm' => (&s[..s.len() - 1], 20),
        b'G' | b'g' => (&s[..s.len() - 1], 30),
        _ => (s, 0),
    };
    let n = match digits.strip_prefix("0x").or_else(|| digits.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16).ok()?,
        None => digits.parse().ok()?,
    };
    n.checked_mul(1 << shift)
}

// Only x86-64 and arm64 have an entry point now. riscv64 gets one later.
#[cfg(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64")))]
static BOOT_INFO: crate::sync::Once<BootInfo> = crate::sync::Once::new();

/// Keeps the boot information and calls the main function of the kernel. The entry code of each
/// architecture calls this function one time, on the boot CPU.
#[cfg(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64")))]
pub(crate) fn start(info: BootInfo) -> ! {
    let info = BOOT_INFO.call_once(|| info);
    unsafe extern "Rust" {
        fn __rk_kernel_main(boot: &'static BootInfo) -> !;
    }
    // SAFETY: `kernel_main!` defines this symbol with this signature. Without it, the kernel does
    // not link. The function is called one time, from the boot CPU.
    unsafe { __rk_kernel_main(info) }
}

/// The boot information, after the entry code gave it to `start`.
#[cfg(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64")))]
pub(crate) fn info() -> Option<&'static BootInfo> {
    BOOT_INFO.get()
}

/// Names the main function of the kernel. The function gets the boot information and does not
/// return.
///
/// ```ignore
/// rk_frame::kernel_main!(main);
/// fn main(boot: &'static rk_frame::boot::BootInfo) -> ! { loop {} }
/// ```
#[macro_export]
macro_rules! kernel_main {
    ($main:path) => {
        #[unsafe(export_name = "__rk_kernel_main")]
        fn __rk_kernel_main(boot: &'static $crate::boot::BootInfo) -> ! {
            $main(boot)
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_line_stops_at_the_limit() {
        let mut info = BootInfo::new("test");
        let mut n = 0;
        while info.push_cmdline_byte(b'a') {
            n += 1;
        }
        assert_eq!(n, COMMAND_LINE_SIZE - 1);
        assert_eq!(info.cmdline().len(), COMMAND_LINE_SIZE - 1);
    }

    #[test]
    fn command_line_ends_at_bad_utf8() {
        let mut info = BootInfo::new("test");
        for b in [b'o', b'k', 0xff, b'x'] {
            info.push_cmdline_byte(b);
        }
        assert_eq!(info.cmdline(), "ok");
    }

    #[test]
    fn usable_memory_is_the_sum_of_usable_regions() {
        let mut info = BootInfo::new("test");
        info.push_region(PhysAddr::new(0), 0x9f000, MemoryKind::Usable);
        info.push_region(PhysAddr::new(0x9f000), 0x1000, MemoryKind::Reserved);
        info.push_region(PhysAddr::new(0x100000), 0x7ff00000, MemoryKind::from_e820(1));
        info.push_region(PhysAddr::new(0x200000), 0, MemoryKind::Usable);
        assert_eq!(info.memory().len(), 3);
        assert_eq!(info.usable_bytes(), 0x9f000 + 0x7ff00000);
    }

    #[test]
    fn initrdmem_gives_the_initramfs() {
        let mut info = BootInfo::new("test");
        for b in b"console=ttyS0 initrdmem=0x4000000,1614696 rk.test=init" {
            info.push_cmdline_byte(*b);
        }
        info.initrd_from_cmdline();
        assert_eq!(info.initrd(), Some((PhysAddr::new(0x400_0000), 1_614_696)));
        // The initramfs of the boot protocol comes first.
        let mut info = BootInfo::new("test");
        for b in b"initrdmem=64M,4K" {
            info.push_cmdline_byte(*b);
        }
        info.initrd_from_cmdline();
        assert_eq!(info.initrd(), Some((PhysAddr::new(64 << 20), 4096)));
        info.set_initrd(PhysAddr::new(0x1000), 1);
        info.initrd_from_cmdline();
        assert_eq!(info.initrd(), Some((PhysAddr::new(0x1000), 1)));
        // A bad value gives no initramfs.
        for bad in
            ["initrdmem=0x10", "initrdmem=x,1", "initrdmem=1,", "initrdmem=0xffffffffffffffff,2"]
        {
            let mut info = BootInfo::new("test");
            for b in bad.as_bytes() {
                info.push_cmdline_byte(*b);
            }
            info.initrd_from_cmdline();
            assert_eq!(info.initrd(), None, "{bad}");
        }
        assert_eq!(memparse("1G"), Some(1 << 30));
        assert_eq!(memparse("0x20k"), Some(32 << 10));
        assert_eq!(memparse(""), None);
    }

    #[test]
    fn adjacent_regions_of_one_kind_merge() {
        let mut info = BootInfo::new("test");
        info.push_region(PhysAddr::new(0), 0x1000, MemoryKind::Usable);
        info.push_region(PhysAddr::new(0x1000), 0x1000, MemoryKind::Usable);
        info.push_region(PhysAddr::new(0x2000), 0x1000, MemoryKind::Reserved);
        info.push_region(PhysAddr::new(0x4000), 0x1000, MemoryKind::Reserved);
        let m = info.memory();
        assert_eq!(m.len(), 3);
        assert_eq!((m[0].start.get(), m[0].len), (0, 0x2000));
        assert_eq!((m[2].start.get(), m[2].len), (0x4000, 0x1000));
    }
}
