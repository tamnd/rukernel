//! The tables of the firmware that sysfs shows in `/sys/firmware`: the SMBIOS tables on x86-64
//! and the device tree on arm64.
//!
//! The frame finds the tables and gives their bytes. The crates above it read the fields.

/// The SMBIOS tables, as `dmi_scan_machine` of Linux finds them: the entry point and the
/// structure table that it points to. Linux shows them in `/sys/firmware/dmi/tables`.
#[derive(Clone, Copy, Debug)]
pub struct Smbios {
    /// The bytes of the entry point: `_SM3_` of 24 bytes, or `_SM_` of 31 bytes.
    pub entry: &'static [u8],
    /// The bytes of the structure table.
    pub table: &'static [u8],
}

/// Gives the SMBIOS tables, if the firmware has them. The first call reads them.
#[must_use]
pub fn smbios() -> Option<Smbios> {
    #[cfg(all(target_os = "none", target_arch = "x86_64"))]
    {
        use crate::sync::Once;
        static TABLES: Once<Option<Smbios>> = Once::new();
        *TABLES.call_once(crate::arch::imp::smbios::find)
    }
    #[cfg(not(all(target_os = "none", target_arch = "x86_64")))]
    {
        None
    }
}

/// Gives the flattened device tree that the boot loader gave, if there is one. The boot path
/// keeps its memory, so the bytes stay the same.
#[must_use]
pub fn device_tree() -> Option<&'static [u8]> {
    #[cfg(all(target_os = "none", target_arch = "aarch64"))]
    {
        crate::arch::imp::boot::device_tree()
    }
    #[cfg(not(all(target_os = "none", target_arch = "aarch64")))]
    {
        None
    }
}
