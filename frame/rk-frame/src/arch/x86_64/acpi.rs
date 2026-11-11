//! The ACPI tables that the kernel reads: the MADT, for the local APIC ID of each CPU, and the
//! `TPM2` table, for the TPM and its event log.
//!
//! The RSDP points to the RSDT or the XSDT, which point to the other tables. The kernel reads the
//! tables through the direct map. A table that is not in the direct map is not read.

use super::paging;
use crate::mm::frame::query;

/// Reads a value at the physical address `addr`, if the direct map has it.
pub(super) fn read<T: Copy>(addr: u64) -> Option<T> {
    let virt = paging::phys_to_virt(addr);
    let last = virt.checked_add(size_of::<T>() - 1)?;
    query(crate::addr::VirtAddr::new(virt))?;
    query(crate::addr::VirtAddr::new(last))?;
    // SAFETY: the two checks tell that the direct map has the first and the last byte of the
    // value, and the value is less than one page. The direct map has RAM and firmware tables
    // only. The value is read unaligned and copied out, and it is a plain integer structure, for
    // which each bit pattern is valid.
    Some(unsafe { core::ptr::read_unaligned(virt as *const T) })
}

/// The header of each ACPI table except the RSDP.
#[repr(C)]
#[derive(Clone, Copy)]
struct Header {
    signature: [u8; 4],
    length: u32,
    revision: u8,
    checksum: u8,
    oem: [u8; 6],
    oem_table: [u8; 8],
    oem_revision: u32,
    creator: u32,
    creator_revision: u32,
}

/// Gives the physical address of the table with the signature `signature`.
fn find_table(signature: &[u8; 4]) -> Option<u64> {
    let rsdp = crate::boot::info()?.rsdp()?.get();
    let revision = read::<u8>(rsdp + 15)?;
    let xsdt = if revision >= 2 { read::<u64>(rsdp + 24)? } else { 0 };
    let (root, entry) = if xsdt != 0 { (xsdt, 8) } else { (u64::from(read::<u32>(rsdp + 16)?), 4) };
    let header = read::<Header>(root)?;
    let count = (u64::from(header.length).saturating_sub(size_of::<Header>() as u64)) / entry;
    (0..count).find_map(|i| {
        let at = root + size_of::<Header>() as u64 + i * entry;
        let table = if entry == 8 { read::<u64>(at)? } else { u64::from(read::<u32>(at)?) };
        (read::<Header>(table)?.signature == *signature).then_some(table)
    })
}

/// The MADT entry of a local APIC and of a local x2APIC.
const MADT_LOCAL_APIC: u8 = 0;
const MADT_LOCAL_X2APIC: u8 = 9;
/// The flag of a MADT entry for a CPU that is on. A CPU that can be put on later is not used.
const MADT_ENABLED: u32 = 1 << 0;

/// Writes the local APIC ID of each CPU that the MADT gives to `ids`, and gives their number. A
/// machine without a MADT gives 0.
pub(crate) fn local_apic_ids(ids: &mut [u32]) -> usize {
    let Some(madt) = find_table(b"APIC") else { return 0 };
    let Some(header) = read::<Header>(madt) else { return 0 };
    let end = madt + u64::from(header.length);
    // The header, the address of the local APIC and the flags.
    let mut at = madt + size_of::<Header>() as u64 + 8;
    let mut n = 0;
    while at + 2 <= end && n < ids.len() {
        let (Some(kind), Some(len)) = (read::<u8>(at), read::<u8>(at + 1)) else { break };
        if len < 2 {
            break;
        }
        let entry = match kind {
            MADT_LOCAL_APIC => read::<u8>(at + 3).map(u32::from).zip(read::<u32>(at + 4)),
            MADT_LOCAL_X2APIC => read::<u32>(at + 4).zip(read::<u32>(at + 8)),
            _ => None,
        };
        if let Some((id, flags)) = entry
            && flags & MADT_ENABLED != 0
            && !ids[..n].contains(&id)
        {
            ids[n] = id;
            n += 1;
        }
        at += u64::from(len);
    }
    n
}

/// The offsets in the `TPM2` table of the address of the CRB control area and of the start method,
/// after the header and the platform class.
const TPM2_CONTROL_AREA: u64 = 40;
const TPM2_START_METHOD: u64 = 48;

/// Gives the address of the CRB control area and the start method of the `TPM2` table, as
/// `crb_acpi_add` of Linux reads them. A machine without the table gives `None`.
pub(crate) fn tpm2() -> Option<(u64, u32)> {
    let table = find_table(b"TPM2")?;
    let header = read::<Header>(table)?;
    if u64::from(header.length) < TPM2_START_METHOD + 4 {
        return None;
    }
    Some((read::<u64>(table + TPM2_CONTROL_AREA)?, read::<u32>(table + TPM2_START_METHOD)?))
}

/// The offsets in the `TPM2` table of the minimum length and of the start address of the log
/// area, after the 12 bytes of the parameters of the start method. A table without them is
/// shorter than `TPM2_LOG_END`.
const TPM2_LOG_LEN: u64 = 64;
const TPM2_LOG_START: u64 = 68;
const TPM2_LOG_END: u64 = 76;

/// Gives the start address and the length of the log area of the `TPM2` table, as
/// `tpm_read_log_acpi` of Linux reads them. A table without a log area, or with an address or a
/// length of 0, gives `None`.
pub(crate) fn tpm2_log() -> Option<(u64, u64)> {
    let table = find_table(b"TPM2")?;
    if u64::from(read::<Header>(table)?.length) < TPM2_LOG_END {
        return None;
    }
    let len = u64::from(read::<u32>(table + TPM2_LOG_LEN)?);
    let start = read::<u64>(table + TPM2_LOG_START)?;
    (start != 0 && len != 0).then_some((start, len))
}

/// Copies `len` bytes at the physical address `addr`, if the direct map has all of them.
pub(crate) fn copy(addr: u64, len: usize) -> Option<alloc::vec::Vec<u8>> {
    const CHUNK: usize = 64;
    let mut out = alloc::vec::Vec::with_capacity(len);
    let mut at = addr;
    while out.len() + CHUNK <= len {
        out.extend_from_slice(&read::<[u8; CHUNK]>(at)?);
        at += CHUNK as u64;
    }
    while out.len() < len {
        out.push(read::<u8>(at)?);
        at += 1;
    }
    Some(out)
}
