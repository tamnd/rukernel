//! Physical and virtual addresses.
//!
//! A physical address and a virtual address are different types. Thus a function that wants one
//! kind of address cannot get the other kind by mistake.

/// The size of the smallest page on each supported architecture.
pub const PAGE_SIZE: usize = 4096;

/// A physical address.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[repr(transparent)]
pub struct PhysAddr(u64);

/// A virtual address.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[repr(transparent)]
pub struct VirtAddr(usize);

impl PhysAddr {
    /// Makes a physical address from a number.
    pub const fn new(addr: u64) -> Self {
        Self(addr)
    }

    /// Gives the address as a number.
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Tells if the address is at the start of a page.
    pub const fn is_page_aligned(self) -> bool {
        self.0.is_multiple_of(PAGE_SIZE as u64)
    }
}

impl VirtAddr {
    /// Makes a virtual address from a number.
    pub const fn new(addr: usize) -> Self {
        Self(addr)
    }

    /// Gives the address as a number.
    pub const fn get(self) -> usize {
        self.0
    }

    /// Tells if the address is at the start of a page.
    pub const fn is_page_aligned(self) -> bool {
        self.0.is_multiple_of(PAGE_SIZE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_alignment() {
        assert!(PhysAddr::new(0x20_0000).is_page_aligned());
        assert!(!PhysAddr::new(0x20_0001).is_page_aligned());
        assert!(VirtAddr::new(PAGE_SIZE * 3).is_page_aligned());
        assert!(!VirtAddr::new(PAGE_SIZE + 8).is_page_aligned());
    }
}
