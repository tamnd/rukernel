//! The windows of the PCI host and of the PCI bridges, and the values of the window registers of a
//! bridge, as drivers/pci/setup-bus.c of Linux. The scan of the PCI bus on arm64 uses them, and
//! the tests run on the host.

/// The granule of the memory windows of a bridge: 1 MiB.
pub(crate) const MEMORY_GRANULE: u64 = 1 << 20;
/// The granule of the I/O window of a bridge: 4 KiB, as `pbus_size_io` of Linux.
pub(crate) const IO_GRANULE: u64 = 1 << 12;
/// The lowest address of an I/O BAR, as `PCIBIOS_MIN_IO` of Linux on arm64.
pub(crate) const MIN_IO: u64 = 0x1000;

/// The free part of a window: the next address and the end.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Window {
    pub(crate) next: u64,
    pub(crate) end: u64,
}

impl Window {
    /// A window with no addresses.
    pub(crate) const EMPTY: Self = Self { next: 0, end: 0 };

    /// The window of the start and the size `w`, or an empty window.
    pub(crate) fn new(w: Option<(u64, u64)>) -> Self {
        w.map_or(Self::EMPTY, |(start, len)| Self { next: start, end: start.saturating_add(len) })
    }

    /// Takes `size` bytes at a multiple of `size`, which is a power of two, below `limit`.
    pub(crate) fn take(&mut self, size: u64, limit: u64) -> Option<u64> {
        let at = self.next.checked_next_multiple_of(size)?;
        let end = at.checked_add(size)?;
        if end > self.end.min(limit) {
            return None;
        }
        self.next = end;
        Some(at)
    }

    /// Moves the next address to the next multiple of `granule`, and gives it.
    pub(crate) fn align(&mut self, granule: u64) -> u64 {
        self.next = self.next.checked_next_multiple_of(granule).unwrap_or(self.end);
        self.next = self.next.min(self.end);
        self.next
    }
}

/// The size of an I/O BAR from the value that it gives after a write of all ones: the lowest
/// bit that is set above the two bits of the type. Gives 0 for a BAR that is not there.
pub(crate) fn io_bar_size(mask: u32) -> u64 {
    let mask = u64::from(mask & !3);
    mask.isolate_lowest_one()
}

/// The value of the memory window register of a bridge for the window from `start` to `end`.
/// The base and the limit hold bits 31 to 20 of the address in bits 15 to 4. A window is open
/// when its base is not above its limit, so an empty window gets a base above its limit.
pub(crate) fn memory_register(start: u64, end: u64) -> u32 {
    if end > start {
        let limit = end - 1;
        (start >> 16 & 0xfff0) as u32 | ((limit >> 16 & 0xfff0) as u32) << 16
    } else {
        0xfff0
    }
}

/// The values of the I/O base and limit registers of a bridge, and of their upper halves, for
/// the window from `start` to `end`, as `pci_setup_bridge_io` of Linux. The base and the limit
/// hold bits 15 to 12 of the address in bits 7 to 4, and the upper halves hold bits 31 to 16.
/// An empty window gets a base above its limit.
pub(crate) fn io_registers(start: u64, end: u64) -> (u16, u32) {
    if end > start {
        let limit = end - 1;
        let low = (start >> 8 & 0xf0) as u16 | ((limit >> 8 & 0xf0) as u16) << 8;
        (low, (start >> 16 & 0xffff) as u32 | ((limit >> 16 & 0xffff) as u32) << 16)
    } else {
        (0xf0, 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn take_aligns_each_bar_to_its_size() {
        let mut w = Window::new(Some((0x1000, 0xf000)));
        assert_eq!(w.take(0x20, 1 << 16), Some(0x1000));
        assert_eq!(w.take(0x100, 1 << 16), Some(0x1100));
        assert_eq!(w.take(0x4, 1 << 16), Some(0x1200));
        assert_eq!(w.take(0x1000, 1 << 16), Some(0x2000));
        assert_eq!(w.next, 0x3000);
    }

    #[test]
    fn take_stops_at_the_end_and_at_the_limit() {
        let mut w = Window::new(Some((0x1000, 0x1000)));
        assert_eq!(w.take(0x2000, u64::MAX), None);
        assert_eq!(w.take(0x800, 0x1800), Some(0x1000));
        assert_eq!(w.take(0x800, 0x1800), None);
        assert_eq!(w.take(0x800, u64::MAX), Some(0x1800));
        let mut empty = Window::EMPTY;
        assert_eq!(empty.take(4, u64::MAX), None);
    }

    #[test]
    fn bridge_io_window_holds_the_bars_behind_it() {
        // The steps of `scan_bridge`: align, the BARs behind the bridge, align.
        let mut io = Window::new(Some((MIN_IO, 0x1_0000 - MIN_IO)));
        assert_eq!(io.take(0x20, 1 << 16), Some(0x1000));
        let start = io.align(IO_GRANULE);
        assert_eq!(start, 0x2000);
        assert_eq!(io.take(0x20, 1 << 16), Some(0x2000));
        assert_eq!(io.take(0x40, 1 << 16), Some(0x2040));
        let end = io.align(IO_GRANULE);
        assert_eq!((start, end), (0x2000, 0x3000));
        assert_eq!(io_registers(start, end), (0x2020, 0));
        // A bridge with no I/O BAR behind it gets an empty window.
        let start = io.align(IO_GRANULE);
        assert_eq!(io.align(IO_GRANULE), start);
        assert_eq!(io_registers(start, start), (0xf0, 0));
        // A full window gives no more addresses.
        let mut full = Window::new(Some((0xf000, 0x1000)));
        assert_eq!(full.take(0x1000, 1 << 16), Some(0xf000));
        assert_eq!(full.align(IO_GRANULE), 0x1_0000);
        assert_eq!(full.take(4, 1 << 16), None);
    }

    #[test]
    fn io_registers_hold_the_upper_half() {
        assert_eq!(io_registers(0x1_2000, 0x1_4000), (0x3020, 0x0001_0001));
        assert_eq!(io_registers(0xf000, 0x1_1000), (0x00f0, 0x0001_0000));
    }

    #[test]
    fn memory_register_holds_the_base_and_the_limit() {
        let mut mem = Window::new(Some((0x1000_0000, 0x2eff_0000)));
        let start = mem.align(MEMORY_GRANULE);
        assert_eq!(mem.take(0x4000, 1 << 32), Some(0x1000_0000));
        let end = mem.align(MEMORY_GRANULE);
        assert_eq!(memory_register(start, end), 0x1000_1000);
        assert_eq!(memory_register(end, end), 0xfff0);
    }

    #[test]
    fn io_bar_size_from_the_mask() {
        assert_eq!(io_bar_size(0xffff_ffe1), 0x20);
        // A function that decodes 16 bits of the address.
        assert_eq!(io_bar_size(0x0000_ff01), 0x100);
        assert_eq!(io_bar_size(0x0000_0001), 0);
        assert_eq!(io_bar_size(0), 0);
    }
}
