//! The SMBIOS tables, per the SMBIOS specification 3.7 section 5.2.
//!
//! A BIOS puts the entry point in the BIOS area at 0xf0000, on a 16 byte boundary. An EFI firmware
//! gives it in the configuration table of the EFI system table. The 64 bit
//! entry point `_SM3_` and the 32 bit entry point `_SM_` give the address and the size of the
//! structure table. As `dmi_scan_machine` of Linux, the kernel looks for `_SM3_` first. The
//! kernel reads the tables through the direct map, and copies them one time.

use super::acpi::read;
use crate::firmware::Smbios;
use alloc::boxed::Box;
use alloc::vec::Vec;

/// The part of the BIOS area where the entry point is.
const AREA: core::ops::Range<u64> = 0xf_0000..0x10_0000;
/// The largest structure table that the kernel copies.
const MAX_TABLE: u32 = 1 << 20;

/// Copies `len` bytes at the physical address `addr`, if the direct map has them.
fn copy(addr: u64, len: u32) -> Option<&'static [u8]> {
    let bytes: Option<Vec<u8>> = (0..u64::from(len)).map(|i| read::<u8>(addr + i)).collect();
    Some(Box::leak(bytes?.into_boxed_slice()))
}

/// Tells if the `len` bytes at `addr` have the sum 0, as each checksum of SMBIOS.
fn sum_is_zero(addr: u64, len: u64) -> bool {
    (0..len).try_fold(0u8, |s, i| read::<u8>(addr + i).map(|b| s.wrapping_add(b))) == Some(0)
}

/// Reads the 64 bit entry point at `at`, as `dmi_smbios3_present` of Linux.
fn smbios3(at: u64) -> Option<Smbios> {
    let len = read::<u8>(at + 6)?;
    if read::<[u8; 5]>(at)? != *b"_SM3_" || len < 24 || !sum_is_zero(at, u64::from(len)) {
        return None;
    }
    let size = read::<u32>(at + 12)?;
    let table = read::<u64>(at + 16)?;
    if size == 0 || size > MAX_TABLE {
        return None;
    }
    Some(Smbios { entry: copy(at, u32::from(len))?, table: copy(table, size)? })
}

/// Reads the 32 bit entry point at `at`, as `dmi_smbios_present` of Linux. The intermediate
/// entry point `_DMI_` at offset 16 gives the table.
fn smbios2(at: u64) -> Option<Smbios> {
    let len = read::<u8>(at + 5)?;
    if read::<[u8; 4]>(at)? != *b"_SM_" || !(0x1e..=0x20).contains(&len) {
        return None;
    }
    if !sum_is_zero(at, u64::from(len))
        || read::<[u8; 5]>(at + 16)? != *b"_DMI_"
        || !sum_is_zero(at + 16, 15)
    {
        return None;
    }
    let size = read::<u16>(at + 0x16)?;
    let table = read::<u32>(at + 0x18)?;
    if size == 0 {
        return None;
    }
    Some(Smbios {
        entry: copy(at, u32::from(len))?,
        table: copy(u64::from(table), u32::from(size))?,
    })
}

/// Finds the SMBIOS tables: at the entry point that the EFI firmware gave, or else in the BIOS
/// area.
pub(crate) fn find() -> Option<Smbios> {
    if let Some(at) = crate::boot::info().and_then(|i| i.smbios()) {
        let at = at.get();
        return smbios3(at).or_else(|| smbios2(at));
    }
    AREA.clone().step_by(16).find_map(smbios3).or_else(|| AREA.step_by(16).find_map(smbios2))
}
