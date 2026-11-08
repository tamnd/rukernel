//! The TPM of the machine: where its registers are and which interface it has.
//!
//! On x86-64 the ACPI `TPM2` table gives the TPM, as `crb_acpi_add` and `tpm_tis_acpi_init` of
//! Linux read it. A start method of 7 is a command response buffer (CRB) with its control area at
//! the address of the table. A start method of 6 is a FIFO interface (TIS) at the fixed address
//! `0xfed40000`. On arm64 the device tree node with `compatible = "tcg,tpm-tis-mmio"` gives a TIS,
//! as `tpm_tis_init` of Linux finds it.
//!
//! rk-drv-tpm sends the commands. This module only finds the registers and maps them.

use crate::iomem::IoMem;

/// The interface of a TPM.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Interface {
    /// The command response buffer interface of the TCG PC Client Platform TPM Profile.
    Crb,
    /// The FIFO interface (TIS) of the TCG PC Client Platform TPM Profile.
    Tis,
}

/// A TPM: its interface and the physical range of its registers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TpmDevice {
    interface: Interface,
    phys: u64,
    len: u64,
    /// The offset of the CRB control area from `phys`. A TIS has 0.
    control: u64,
}

/// The physical address and the size of the TIS registers on a PC: five localities of 4 KiB.
#[cfg(target_arch = "x86_64")]
const PC_TIS_BASE: u64 = 0xfed4_0000;
const TIS_SIZE: u64 = 0x5000;
/// The size of the CRB registers of locality 0, which hold the control area.
#[cfg(target_arch = "x86_64")]
const CRB_SIZE: u64 = 0x1000;

/// The start methods of the ACPI `TPM2` table.
#[cfg(target_arch = "x86_64")]
const START_METHOD_TIS: u32 = 6;
#[cfg(target_arch = "x86_64")]
const START_METHOD_CRB: u32 = 7;

impl TpmDevice {
    /// The interface of the TPM.
    pub fn interface(&self) -> Interface {
        self.interface
    }

    /// The physical address of the registers.
    pub fn phys(&self) -> u64 {
        self.phys
    }

    /// The offset of the CRB control area in the registers. A TIS gives 0.
    pub fn control_offset(&self) -> usize {
        self.control as usize
    }

    /// Maps the registers. Gives `None` if the range is on RAM or the kernel cannot map it.
    pub fn map(&self) -> Option<IoMem> {
        map_device(self.phys, self.len)
    }

    /// Maps a command or response buffer of `len` bytes at the physical address `phys`, which
    /// the CRB control area gives. Gives `None` if the range is on RAM or the kernel cannot map
    /// it.
    pub fn map_buffer(&self, phys: u64, len: usize) -> Option<IoMem> {
        map_device(phys, len as u64)
    }
}

/// Gives the TPM of the machine, or `None` if the firmware tables give none.
#[cfg(target_arch = "x86_64")]
pub fn tpm() -> Option<TpmDevice> {
    let (control, method) = crate::arch::imp::acpi::tpm2()?;
    match method {
        START_METHOD_CRB if control != 0 => {
            let phys = control & !(CRB_SIZE - 1);
            Some(TpmDevice {
                interface: Interface::Crb,
                phys,
                len: CRB_SIZE,
                control: control - phys,
            })
        }
        START_METHOD_TIS => Some(TpmDevice {
            interface: Interface::Tis,
            phys: PC_TIS_BASE,
            len: TIS_SIZE,
            control: 0,
        }),
        _ => None,
    }
}

/// Gives the TPM of the machine, or `None` if the device tree gives none.
#[cfg(target_arch = "aarch64")]
pub fn tpm() -> Option<TpmDevice> {
    let (phys, len) = (*TIS.lock())?;
    Some(TpmDevice { interface: Interface::Tis, phys, len: len.max(TIS_SIZE), control: 0 })
}

/// The physical address and the size of the TIS of the device tree.
#[cfg(target_arch = "aarch64")]
static TIS: crate::sync::SpinLock<Option<(u64, u64)>> = crate::sync::SpinLock::new(None);

/// Keeps the TIS of the device tree. The boot path calls this.
#[cfg(target_arch = "aarch64")]
pub(crate) fn set_tis(phys: u64, len: u64) {
    *TIS.lock() = Some((phys, len));
}

/// Maps `len` bytes of device registers at `phys`, if the range is not on RAM.
#[cfg(target_arch = "x86_64")]
fn map_device(phys: u64, len: u64) -> Option<IoMem> {
    use crate::addr::PAGE_SIZE;
    use crate::boot::MemoryKind;
    let end = phys.checked_add(len)?;
    let ram = crate::boot::info()?.memory().iter().any(|r| {
        matches!(
            r.kind,
            MemoryKind::Usable
                | MemoryKind::AcpiReclaimable
                | MemoryKind::AcpiNvs
                | MemoryKind::Persistent
        ) && phys < r.start.get() + r.len
            && r.start.get() < end
    });
    if len == 0 || phys < 1 << 20 || ram {
        return None;
    }
    let len = usize::try_from(len).ok()?;
    let page = phys & !(PAGE_SIZE as u64 - 1);
    let in_page = (phys - page) as usize;
    let virt = crate::mm::frame::vmap_mmio_pages(page, (in_page + len).div_ceil(PAGE_SIZE))?;
    // SAFETY: the pages map the device registers without cache, and the check above tells that
    // they are not RAM.
    Some(unsafe { IoMem::new(virt + in_page, len) })
}

/// Maps `len` bytes of device registers at `phys`. `map_device` of the page tables does not map
/// a range that holds RAM.
#[cfg(target_arch = "aarch64")]
fn map_device(phys: u64, len: u64) -> Option<IoMem> {
    let size = usize::try_from(len).ok().filter(|&l| l > 0)?;
    let info = crate::boot::info()?;
    let virt = crate::arch::imp::paging::map_device(phys, len, info)?;
    // SAFETY: `map_device` maps the range as device memory for all of the run time, and it does
    // not map a range that holds RAM.
    Some(unsafe { IoMem::new(virt, size) })
}
