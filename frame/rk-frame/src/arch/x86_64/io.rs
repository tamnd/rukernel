//! Port I/O.
//!
//! A write to a wrong port can change any device, so only this crate makes a `Port`. Each `Port`
//! names one register of one device that rk-frame owns.

use core::arch::asm;

/// One 8 bit I/O port.
#[derive(Clone, Copy)]
pub(crate) struct Port(u16);

impl Port {
    /// Names a port.
    ///
    /// # Safety
    ///
    /// The port must be a register of a device that this crate owns, and reads and writes to it
    /// must not break the memory safety of the kernel. A legacy UART or the QEMU exit device is
    /// correct. A DMA controller is not.
    pub(crate) const unsafe fn new(port: u16) -> Self {
        Self(port)
    }

    /// Reads one byte.
    pub(crate) fn read(self) -> u8 {
        let value: u8;
        // SAFETY: `Port::new` makes sure that the port is a device register without memory side
        // effects. `in` does not touch memory or the stack.
        unsafe {
            asm!("in al, dx", out("al") value, in("dx") self.0, options(nomem, nostack, preserves_flags));
        }
        value
    }

    /// Writes one byte.
    pub(crate) fn write(self, value: u8) {
        // SAFETY: as for `read`. `out` does not touch memory or the stack.
        unsafe {
            asm!("out dx, al", in("dx") self.0, in("al") value, options(nomem, nostack, preserves_flags));
        }
    }

    /// Writes four bytes.
    pub(crate) fn write_u32(self, value: u32) {
        // SAFETY: as for `read`. `out` does not touch memory or the stack.
        unsafe {
            asm!("out dx, eax", in("dx") self.0, in("eax") value, options(nomem, nostack, preserves_flags));
        }
    }

    /// Writes two bytes.
    pub(crate) fn write_u16(self, value: u16) {
        // SAFETY: as for `read`. `out` does not touch memory or the stack.
        unsafe {
            asm!("out dx, ax", in("dx") self.0, in("ax") value, options(nomem, nostack, preserves_flags));
        }
    }

    /// Reads four bytes.
    pub(crate) fn read_u32(self) -> u32 {
        let value: u32;
        // SAFETY: as for `read`. `in` does not touch memory or the stack.
        unsafe {
            asm!("in eax, dx", out("eax") value, in("dx") self.0, options(nomem, nostack, preserves_flags));
        }
        value
    }
}
