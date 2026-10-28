//! The interrupts of PCI devices through MSI-X, per section 6.8.2 of the PCI Local Bus
//! Specification 3.0 and section 11.11 of the Intel SDM, volume 3.
//!
//! A function with the MSI-X capability writes a message to the local APIC for each interrupt. The
//! message address selects the CPU and the message data is the vector. Each line gets one vector
//! from `FIRST_VECTOR`, and the entry of the MSI-X table of the function that sends it. The handler
//! masks the entry and sets the flag of the vector, as the handler of an SPI on arm64 does. A
//! message that comes while the entry is masked stays pending in the function, and the function
//! sends it when the driver unmasks the entry.

use super::{apic, cpu};
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

/// The first vector of the device lines. The vectors below it are for the exceptions and for the
/// 8259 PICs, which are masked.
pub(crate) const FIRST_VECTOR: u8 = 0x40;
/// The number of device lines.
const LINES: usize = 32;

/// The virtual address of the MSI-X table entry of each line, or 0 for a free vector.
static ENTRY: [AtomicUsize; LINES] = [const { AtomicUsize::new(0) }; LINES];
/// The local APIC ID that the message address of each line selects.
static TARGET: [AtomicU32; LINES] = [const { AtomicU32::new(0) }; LINES];
/// A bit for each line that came since the last `take`.
static FIRED: AtomicU32 = AtomicU32::new(0);

/// The fields of an entry of the MSI-X table.
const ENTRY_ADDR_LOW: usize = 0;
const ENTRY_ADDR_HIGH: usize = 4;
const ENTRY_DATA: usize = 8;
const ENTRY_CONTROL: usize = 12;
/// The bit of the vector control field that masks the entry.
const CONTROL_MASKED: u32 = 1;
/// The size of an entry.
pub(crate) const ENTRY_SIZE: usize = 16;
/// The message address of the local APICs. Bits 19 to 12 are the APIC ID of the target CPU, and
/// the other bits 0 select the physical destination mode.
const MSG_ADDR: u32 = 0xfee0_0000;

fn line(vector: u8) -> Option<usize> {
    let n = usize::from(vector.checked_sub(FIRST_VECTOR)?);
    (n < LINES).then_some(n)
}

/// Writes the field at `offset` of the MSI-X table entry at the virtual address `entry`.
fn write(entry: usize, offset: usize, value: u32) {
    // SAFETY: `entry` is an entry of an MSI-X table that `pci::map_registers` mapped without cache
    // for all of the run time, and it is not RAM. The offset is in the entry and aligned.
    unsafe { ((entry + offset) as *mut u32).write_volatile(value) };
}

/// Sets up the MSI-X table entries at the virtual addresses `entries`, each with a free vector,
/// to the boot CPU and unmasked. Writes the vector of each entry to `vectors`. Gives `false` if
/// not enough vectors are free. Then no entry has a vector.
pub(crate) fn alloc(entries: &[usize], vectors: &mut [u8]) -> bool {
    if vectors.len() < entries.len() {
        return false;
    }
    for (k, &entry) in entries.iter().enumerate() {
        let free = ENTRY.iter().position(|e| {
            e.compare_exchange(0, entry, Ordering::AcqRel, Ordering::Relaxed).is_ok()
        });
        let Some(n) = free else {
            vectors[..k].iter().for_each(|&v| free_vector(v));
            return false;
        };
        vectors[k] = FIRST_VECTOR + n as u8;
    }
    let target = cpu::apic_id(0);
    for (&entry, &vector) in entries.iter().zip(vectors.iter()) {
        let n = usize::from(vector - FIRST_VECTOR);
        TARGET[n].store(target, Ordering::Relaxed);
        write(entry, ENTRY_CONTROL, CONTROL_MASKED);
        write(entry, ENTRY_ADDR_LOW, MSG_ADDR | (target & 0xff) << 12);
        write(entry, ENTRY_ADDR_HIGH, 0);
        // Bits 10 to 8 of the data are 0 for the fixed delivery mode, and bit 15 is 0 for an edge.
        write(entry, ENTRY_DATA, u32::from(vector));
        write(entry, ENTRY_CONTROL, 0);
    }
    true
}

/// Masks the entry of the line `vector` and makes the vector free.
fn free_vector(vector: u8) {
    let Some(n) = line(vector) else { return };
    let entry = ENTRY[n].load(Ordering::Acquire);
    if entry != 0 {
        write(entry, ENTRY_CONTROL, CONTROL_MASKED);
    }
    ENTRY[n].store(0, Ordering::Release);
    FIRED.fetch_and(!(1 << n), Ordering::AcqRel);
}

/// Gives back the lines `vectors`, which `alloc` gave.
pub(crate) fn free(vectors: &[u8]) {
    vectors.iter().for_each(|&v| free_vector(v));
}

/// The handler of a device line: masks the entry and sets the flag of the line. It takes no lock.
/// Gives `false` for another vector.
pub(crate) fn handle(vector: u8) -> bool {
    let Some(n) = line(vector) else { return false };
    let entry = ENTRY[n].load(Ordering::Acquire);
    if entry == 0 {
        return false;
    }
    write(entry, ENTRY_CONTROL, CONTROL_MASKED);
    FIRED.fetch_or(1 << n, Ordering::AcqRel);
    apic::eoi();
    true
}

/// Tells if the line `vector` came since the last `take`.
pub(crate) fn fired(vector: u8) -> bool {
    line(vector).is_some_and(|n| FIRED.load(Ordering::Acquire) & 1 << n != 0)
}

/// Tells if the line `vector` came since the last `take`, and clears the flag.
pub(crate) fn take(vector: u8) -> bool {
    line(vector).is_some_and(|n| FIRED.fetch_and(!(1 << n), Ordering::AcqRel) & 1 << n != 0)
}

/// Unmasks the entry of the line `vector`.
pub(crate) fn unmask(vector: u8) {
    if let Some(n) = line(vector) {
        let entry = ENTRY[n].load(Ordering::Acquire);
        if entry != 0 {
            write(entry, ENTRY_CONTROL, 0);
        }
    }
}

/// Sends the line `vector` to this CPU. The entry is masked while its address changes, and it
/// stays masked if the line came, until `unmask`.
pub(crate) fn route_here(vector: u8) {
    let Some(n) = line(vector) else { return };
    let entry = ENTRY[n].load(Ordering::Acquire);
    let target = cpu::apic_id(cpu::id());
    // The message address has 8 bits for the APIC ID.
    if entry == 0 || target > 0xff || TARGET[n].swap(target, Ordering::Relaxed) == target {
        return;
    }
    write(entry, ENTRY_CONTROL, CONTROL_MASKED);
    write(entry, ENTRY_ADDR_LOW, MSG_ADDR | target << 12);
    if FIRED.load(Ordering::Acquire) & 1 << n == 0 {
        write(entry, ENTRY_CONTROL, 0);
    }
}
