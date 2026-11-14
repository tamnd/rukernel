//! The tables of the firmware that sysfs shows in `/sys/firmware`: the SMBIOS and the ACPI tables
//! on x86-64 and the device tree on arm64.
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

/// A copy of one ACPI table, as Linux shows it in `/sys/firmware/acpi/tables`.
#[derive(Clone, Debug)]
pub struct AcpiTable {
    /// The signature of the table, for example `DSDT` or `TPM2`.
    pub signature: [u8; 4],
    /// All the bytes of the table, with its header. The kernel copies the tables once and keeps
    /// the copies.
    pub bytes: &'static [u8],
}

/// Gives a copy of each ACPI table: the tables of the RSDT or the XSDT, and the DSDT and the FACS
/// that the FADT points to. A machine without ACPI gives none. The first call copies them.
#[must_use]
pub fn acpi_tables() -> &'static [AcpiTable] {
    #[cfg(all(target_os = "none", target_arch = "x86_64"))]
    {
        use crate::sync::Once;
        static TABLES: Once<alloc::vec::Vec<AcpiTable>> = Once::new();
        TABLES.call_once(crate::arch::imp::acpi::tables)
    }
    #[cfg(not(all(target_os = "none", target_arch = "x86_64")))]
    {
        &[]
    }
}

/// Tells if the kernel started from EFI firmware, as `efi_enabled(EFI_BOOT)` of Linux. Linux
/// then has `/sys/firmware/efi`.
#[must_use]
pub fn efi_boot() -> bool {
    #[cfg(all(target_os = "none", target_arch = "x86_64"))]
    {
        crate::boot::info().is_some_and(|info| info.protocol() == "efi")
    }
    #[cfg(not(all(target_os = "none", target_arch = "x86_64")))]
    {
        false
    }
}
