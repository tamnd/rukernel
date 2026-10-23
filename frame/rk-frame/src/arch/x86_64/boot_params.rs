//! The `boot_params` structure of the Linux boot protocol.
//!
//! A loader of a bzImage gives the kernel a `boot_params` structure, the "zero page". It has the
//! setup header of the image, the E820 memory map, the command line and the initramfs, per
//! Documentation/arch/x86/boot.rst and Documentation/arch/x86/zero-page.rst in the Linux tree.
//! This module reads the fields that the kernel uses. The offsets are the offsets of Linux.

use super::boot::read_phys;
use crate::addr::PhysAddr;
use crate::boot::{BootInfo, MemoryKind};

/// `acpi_rsdp_addr`: the physical address of the ACPI RSDP, or 0. Protocol 2.14 and later.
const ACPI_RSDP_ADDR: u64 = 0x070;
/// `ext_ramdisk_image`, `ext_ramdisk_size` and `ext_cmd_line_ptr`: the high 32 bits.
const EXT_RAMDISK_IMAGE: u64 = 0x0c0;
const EXT_RAMDISK_SIZE: u64 = 0x0c4;
const EXT_CMD_LINE_PTR: u64 = 0x0c8;
/// `efi_loader_signature`: "EL64" when the EFI stub of a 64 bit kernel made the structure.
const EFI_LOADER_SIGNATURE: u64 = 0x1c0;
/// `e820_entries`: the number of entries in `e820_table`.
const E820_ENTRIES: u64 = 0x1e8;
/// The setup header fields.
const HEADER_MAGIC: u64 = 0x202;
const RAMDISK_IMAGE: u64 = 0x218;
const RAMDISK_SIZE: u64 = 0x21c;
const CMD_LINE_PTR: u64 = 0x228;
/// `e820_table`: 128 entries of 20 bytes.
const E820_TABLE: u64 = 0x2d0;
const E820_MAX_ENTRIES: u8 = 128;
const E820_ENTRY_SIZE: u64 = 20;

/// "HdrS", the magic number of the setup header.
const HDRS: u32 = 0x5372_6448;
/// "EL64".
const EL64: u32 = 0x3436_4c45;

/// The BIOS area where the RSDP can be, if the loader does not give it.
const BIOS_ROM: core::ops::Range<u64> = 0xe_0000..0x10_0000;
/// "RSD PTR ", the signature of the RSDP.
const RSDP_SIGNATURE: u64 = 0x2052_5450_2044_5352;

fn read_u32(base: u64, offset: u64) -> u32 {
    read_phys::<u32>(base + offset).unwrap_or(0)
}

fn read_u64(base: u64, offset: u64) -> u64 {
    read_phys::<u64>(base + offset).unwrap_or(0)
}

/// Reads the `boot_params` at the physical address `base`.
pub(super) fn read(base: u64) -> BootInfo {
    let protocol = if read_u32(base, EFI_LOADER_SIGNATURE) == EL64 { "efi" } else { "linux" };
    let mut info = BootInfo::new(protocol);
    if read_u32(base, HEADER_MAGIC) != HDRS {
        return info;
    }

    let cmdline =
        u64::from(read_u32(base, CMD_LINE_PTR)) | u64::from(read_u32(base, EXT_CMD_LINE_PTR)) << 32;
    if cmdline != 0 {
        let mut p = cmdline;
        while let Some(b) = read_phys::<u8>(p) {
            if b == 0 || !info.push_cmdline_byte(b) {
                break;
            }
            p += 1;
        }
    }

    let entries = read_phys::<u8>(base + E820_ENTRIES).unwrap_or(0).min(E820_MAX_ENTRIES);
    for i in 0..u64::from(entries) {
        let at = base + E820_TABLE + i * E820_ENTRY_SIZE;
        let (addr, size, kind) = (read_u64(at, 0), read_u64(at, 8), read_u32(at, 16));
        info.push_region(PhysAddr::new(addr), size, MemoryKind::from_e820(kind));
    }

    let image = u64::from(read_u32(base, RAMDISK_IMAGE))
        | u64::from(read_u32(base, EXT_RAMDISK_IMAGE)) << 32;
    let size =
        u64::from(read_u32(base, RAMDISK_SIZE)) | u64::from(read_u32(base, EXT_RAMDISK_SIZE)) << 32;
    if image != 0 && size != 0 {
        info.set_initrd(PhysAddr::new(image), size);
    }

    match read_u64(base, ACPI_RSDP_ADDR) {
        0 => {
            if let Some(rsdp) = find_rsdp() {
                info.set_rsdp(PhysAddr::new(rsdp));
            }
        }
        rsdp => info.set_rsdp(PhysAddr::new(rsdp)),
    }
    info
}

/// Finds the RSDP in the BIOS area, on a 16 byte boundary, as the ACPI specification tells. A
/// loader on a BIOS machine does not have to give the RSDP.
fn find_rsdp() -> Option<u64> {
    BIOS_ROM.step_by(16).find(|&a| read_phys::<u64>(a) == Some(RSDP_SIGNATURE))
}
