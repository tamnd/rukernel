//! The ACPI tables that the kernel reads: the MADT, for the local APIC ID of each CPU.
//!
//! The RSDP points to the RSDT or the XSDT, which point to the other tables. The kernel reads the
//! tables through the direct map. A table that is not in the direct map is not read.

use super::paging;
use crate::mm::frame::query;

/// Reads a value at the physical address `addr`, if the direct map has it.
fn read<T: Copy>(addr: u64) -> Option<T> {
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
