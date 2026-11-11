//! The TPM 2.0 driver of rukernel, as drivers/char/tpm of Linux.
//!
//! rk-frame finds the TPM: the ACPI `TPM2` table on x86-64, and the device tree node with
//! `compatible = "tcg,tpm-tis-mmio"` on arm64. This crate sends the commands through the command
//! response buffer (CRB) interface of `crb`, as tpm_crb.c, or through the FIFO interface (TIS) of
//! `tis`, as tpm_tis_core.c. Each step waits up to the time limits of the TCG PC Client Platform
//! TPM Profile, and each command waits up to its duration of `cmd::duration`. The driver does not
//! use the interrupt of the TPM. It reads the status again after each tick, as Linux does for a
//! TPM without an interrupt.
//!
//! The chip sends one command at a time. At boot `init` does the startup of Linux
//! (`tpm2_auto_startup`): `TPM2_SelfTest`, and `TPM2_Startup` if the TPM is not started. It reads
//! the attributes of the commands for the resource manager of `space`. Then it adds `/dev/tpm0`,
//! `/dev/tpmrm0` and their directories in sysfs, with `dev`.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod cmd;
pub mod crb;
pub mod dev;
pub mod space;
#[cfg(test)]
mod tests;
pub mod tis;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_frame::sync::SpinLock;
use rk_vfs::wait::WaitQueue;

/// The result of a TPM operation.
pub type Result<T> = core::result::Result<T, Errno>;

// The time limits of the TCG PC Client Platform TPM Profile for TPM 2.0 in milliseconds, as
// `TPM2_TIMEOUT_*` of Linux.

/// The time limit for a change of locality, as `TPM2_TIMEOUT_A` of Linux.
pub const TIMEOUT_A: u64 = 750;
/// The time limit for the start of a command, as `TPM2_TIMEOUT_B` of Linux.
pub const TIMEOUT_B: u64 = 2000;
/// The time limit for a change of status, as `TPM2_TIMEOUT_C` of Linux.
pub const TIMEOUT_C: u64 = 200;
/// The time limit for a short step, as `TPM2_TIMEOUT_D` of Linux.
pub const TIMEOUT_D: u64 = 30;

/// The registers of a TPM. The kernel uses an `IoMem`, and the tests use a model of a TPM.
pub trait Regs: Send {
    /// The size of the registers in bytes.
    fn size(&self) -> usize;
    /// Reads the byte register at `offset`.
    fn read_u8(&self, offset: usize) -> u8;
    /// Reads the 32-bit register at `offset`.
    fn read_u32(&self, offset: usize) -> u32;
    /// Writes the byte register at `offset`.
    fn write_u8(&self, offset: usize, value: u8);
    /// Writes the 32-bit register at `offset`.
    fn write_u32(&self, offset: usize, value: u32);
}

#[cfg(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64")))]
impl Regs for rk_frame::iomem::IoMem {
    fn size(&self) -> usize {
        rk_frame::iomem::IoMem::len(self)
    }
    fn read_u8(&self, offset: usize) -> u8 {
        rk_frame::iomem::IoMem::read_u8(self, offset)
    }
    fn read_u32(&self, offset: usize) -> u32 {
        rk_frame::iomem::IoMem::read_u32(self, offset)
    }
    fn write_u8(&self, offset: usize, value: u8) {
        rk_frame::iomem::IoMem::write_u8(self, offset, value);
    }
    fn write_u32(&self, offset: usize, value: u32) {
        rk_frame::iomem::IoMem::write_u32(self, offset, value);
    }
}

/// The clock of the waits.
pub trait Clock: Send + Sync {
    /// The time in milliseconds from a fixed point.
    fn now_ms(&self) -> u64;
    /// Waits a short time before the next read of a status: one tick in the kernel.
    fn sleep(&self);
}

/// Tests `cond` until it is true, and sleeps between two tests. Gives `ETIME` if it is not true
/// after `ms` milliseconds. It tests one more time at the end, as `wait_for_tpm_stat` of Linux.
pub(crate) fn poll(clock: &dyn Clock, ms: u64, mut cond: impl FnMut() -> bool) -> Result<()> {
    let stop = clock.now_ms().saturating_add(ms);
    loop {
        if cond() {
            return Ok(());
        }
        if clock.now_ms() > stop {
            return if cond() { Ok(()) } else { Err(Errno::ETIME) };
        }
        clock.sleep();
    }
}

/// An interface of a TPM.
pub trait Transport: Send {
    /// Sends the command `cmd`, waits up to `duration` milliseconds for the TPM, and copies the
    /// response to `rsp`. Gives the size of the response.
    ///
    /// # Errors
    ///
    /// `ETIME` if the TPM does not answer in time, `EIO` for a bad response, and `E2BIG` for a
    /// command that is too large for the TPM.
    fn transmit(
        &mut self,
        clock: &dyn Clock,
        cmd: &[u8],
        rsp: &mut [u8],
        duration: u64,
    ) -> Result<usize>;

    /// The name of the interface, as the name of the Linux driver: `tpm_crb` or `tpm_tis`.
    fn name(&self) -> &'static str;
}

/// A TPM chip. It sends one command at a time: a second caller waits.
pub struct Chip {
    transport: SpinLock<Option<Box<dyn Transport>>>,
    free: WaitQueue,
    clock: Box<dyn Clock>,
    name: &'static str,
    /// The attributes of the commands of the TPM, as `cc_attrs_tbl` of Linux. `read_cc_attrs`
    /// fills it.
    cc_attrs: SpinLock<Vec<u32>>,
}

/// A chip that one caller has. Other callers wait until the guard goes, so that the commands of
/// the caller have no other commands between them, as `tpm_try_get_ops` of Linux.
pub struct ChipGuard<'a> {
    chip: &'a Chip,
    transport: Option<Box<dyn Transport>>,
}

impl Drop for ChipGuard<'_> {
    fn drop(&mut self) {
        *self.chip.transport.lock() = self.transport.take();
        self.chip.free.wake_all();
    }
}

impl ChipGuard<'_> {
    /// Sends the command `cmd` and copies the response to `rsp`, as `tpm_transmit` of Linux. The
    /// command waits up to its duration. A response of `TPM_RC_RETRY` or `TPM_RC_TESTING` sends
    /// the command again after a wait that doubles each time, up to the long duration. Gives the
    /// size of the response.
    ///
    /// # Errors
    ///
    /// `EINVAL` for a command that is shorter than a header, `E2BIG` for a command whose size
    /// field is not its length or is too large, `EFAULT` for a response whose size field is not
    /// its length, and the errors of `Transport::transmit`.
    pub fn transmit(&mut self, cmd: &[u8], rsp: &mut [u8]) -> Result<usize> {
        if cmd.len() < cmd::HEADER_SIZE {
            return Err(Errno::EINVAL);
        }
        if cmd.len() > cmd::BUFSIZE || cmd::size(cmd) != Some(cmd.len()) {
            return Err(Errno::E2BIG);
        }
        let clock = &*self.chip.clock;
        let t = self.transport.as_mut().ok_or(Errno::ENODEV)?;
        let cc = cmd::code(cmd).unwrap_or(0);
        let duration = cmd::duration(cc);
        let mut delay = cmd::DURATION_SHORT;
        loop {
            let n = match t.transmit(clock, cmd, rsp, duration) {
                Ok(n) if n >= cmd::HEADER_SIZE && cmd::size(rsp) == Some(n) => n,
                Ok(_) => return Err(Errno::EFAULT),
                Err(e) => return Err(e),
            };
            let rc = cmd::code(rsp).unwrap_or(0);
            if rc != cmd::RC_RETRY && rc != cmd::RC_TESTING {
                return Ok(n);
            }
            // A self test that runs gives its answer at once, so that the boot is not slower.
            if (rc == cmd::RC_TESTING && cc == cmd::CC_SELF_TEST) || delay > cmd::DURATION_LONG {
                return Ok(n);
            }
            let stop = clock.now_ms() + delay;
            while clock.now_ms() < stop {
                clock.sleep();
            }
            delay *= 2;
        }
    }

    /// Sends the command `cmd` and gives the response and its response code.
    ///
    /// # Errors
    ///
    /// The errors of `transmit`.
    pub fn command(&mut self, cmd: &[u8]) -> Result<(u32, Vec<u8>)> {
        let mut rsp = vec![0u8; cmd::BUFSIZE];
        let n = self.transmit(cmd, &mut rsp)?;
        rsp.truncate(n);
        Ok((cmd::code(&rsp).unwrap_or(0), rsp))
    }

    /// The chip.
    pub fn chip(&self) -> &Chip {
        self.chip
    }
}

impl Chip {
    /// Makes a chip with the interface `transport`.
    pub fn new(transport: Box<dyn Transport>, clock: Box<dyn Clock>) -> Self {
        let name = transport.name();
        Self {
            transport: SpinLock::new(Some(transport)),
            free: WaitQueue::new(),
            clock,
            name,
            cc_attrs: SpinLock::new(Vec::new()),
        }
    }

    /// The name of the interface.
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// Waits until no other caller has the chip, and gives it to this caller.
    pub fn lock(&self) -> ChipGuard<'_> {
        let t = self.free.wait_until(|| self.transport.lock().take());
        ChipGuard { chip: self, transport: Some(t) }
    }

    /// Sends the command `cmd` and copies the response to `rsp`, as `ChipGuard::transmit`.
    ///
    /// # Errors
    ///
    /// The errors of `ChipGuard::transmit`.
    pub fn transmit(&self, cmd: &[u8], rsp: &mut [u8]) -> Result<usize> {
        self.lock().transmit(cmd, rsp)
    }

    /// Sends the command `cmd` and gives the response and its response code.
    ///
    /// # Errors
    ///
    /// The errors of `transmit`.
    pub fn command(&self, cmd: &[u8]) -> Result<(u32, Vec<u8>)> {
        self.lock().command(cmd)
    }

    /// Reads the attributes of all of the commands of the TPM with `TPM2_GetCapability`, as
    /// `tpm2_get_cc_attrs_tbl` of Linux. `TPM2_ContextSave` and `TPM2_FlushContext` get one
    /// handle, because the resource manager must change the handle in their parameter too.
    ///
    /// # Errors
    ///
    /// The errors of `transmit`, and `EIO` for an error of the TPM or a bad response.
    pub fn read_cc_attrs(&self) -> Result<()> {
        let mut attrs = Vec::new();
        let mut next = cmd::CC_FIRST;
        loop {
            let (rc, rsp) = self.command(&cmd::get_capability(cmd::CAP_COMMANDS, next, 256))?;
            if rc != cmd::RC_SUCCESS {
                return Err(Errno::EIO);
            }
            let (more, values) =
                cmd::parse_capability_u32(&rsp, cmd::CAP_COMMANDS).ok_or(Errno::EIO)?;
            let Some(&last) = values.last() else { break };
            attrs.extend(values);
            next = (last & 0xffff) + 1;
            if !more || attrs.len() > 0xffff {
                break;
            }
        }
        for a in &mut attrs {
            let cc = *a & 0xffff;
            if cc == cmd::CC_CONTEXT_SAVE || cc == cmd::CC_FLUSH_CONTEXT {
                *a = (*a & !(7 << cmd::CC_ATTR_CHANDLES)) | (1 << cmd::CC_ATTR_CHANDLES);
            }
        }
        *self.cc_attrs.lock() = attrs;
        Ok(())
    }

    /// The attributes of the command with the code `cc`, as `tpm2_find_cc` of Linux. A command
    /// of the vendor has the bit `CC_ATTR_VENDOR` in its code.
    pub fn cc_attrs(&self, cc: u32) -> Option<u32> {
        let mask = (1 << cmd::CC_ATTR_VENDOR) | 0xffff;
        self.cc_attrs.lock().iter().copied().find(|a| a & mask == cc)
    }

    /// Tells if `read_cc_attrs` read the attributes of the commands.
    pub fn has_cc_attrs(&self) -> bool {
        !self.cc_attrs.lock().is_empty()
    }

    /// Sends `TPM2_SelfTest`, first a test of the functions that are not tested yet, then a full
    /// test, as `tpm2_do_selftest` of Linux. A test that runs counts as success. Gives the
    /// response code.
    fn self_test(&self) -> Result<u32> {
        let mut rc = cmd::RC_SUCCESS;
        for full in [false, true] {
            rc = self.command(&cmd::self_test(full))?.0;
            if rc == cmd::RC_TESTING {
                rc = cmd::RC_SUCCESS;
            }
            if rc == cmd::RC_SUCCESS || rc == cmd::RC_INITIALIZE {
                break;
            }
        }
        Ok(rc)
    }

    /// Starts the TPM if the firmware did not, as `tpm2_auto_startup` of Linux: a self test, and
    /// if the TPM is not started, `TPM2_Startup(TPM_SU_CLEAR)` and a self test again. Gives `true`
    /// if it sent `TPM2_Startup`.
    ///
    /// # Errors
    ///
    /// The errors of `transmit`, and `ENODEV` if the TPM gives an error.
    pub fn auto_startup(&self) -> Result<bool> {
        let rc = self.self_test()?;
        if rc == cmd::RC_SUCCESS {
            return Ok(false);
        }
        if rc != cmd::RC_INITIALIZE {
            return Err(Errno::ENODEV);
        }
        self.startup()?;
        match self.self_test()? {
            cmd::RC_SUCCESS => Ok(true),
            _ => Err(Errno::ENODEV),
        }
    }

    /// Sends `TPM2_Startup(TPM_SU_CLEAR)`. A TPM that was started already gives
    /// `TPM_RC_INITIALIZE`, and that counts as success too. Gives the response code.
    ///
    /// # Errors
    ///
    /// The errors of `transmit`, and `EIO` for another response code.
    pub fn startup(&self) -> Result<u32> {
        match self.command(&cmd::startup(cmd::SU_CLEAR))?.0 {
            rc @ (cmd::RC_SUCCESS | cmd::RC_INITIALIZE) => Ok(rc),
            _ => Err(Errno::EIO),
        }
    }

    /// Fills `out` with random bytes of the TPM, as `tpm2_get_random` of Linux.
    ///
    /// # Errors
    ///
    /// The errors of `transmit`, and `EIO` for an error of the TPM or a response with no bytes.
    pub fn get_random(&self, out: &mut [u8]) -> Result<()> {
        let mut done = 0;
        while done < out.len() {
            let want = u16::try_from(out.len() - done).unwrap_or(u16::MAX).min(128);
            let (rc, rsp) = self.command(&cmd::get_random(want))?;
            let bytes = cmd::parse_random(&rsp).filter(|b| rc == 0 && !b.is_empty());
            let bytes = bytes.ok_or(Errno::EIO)?;
            let n = bytes.len().min(out.len() - done);
            out[done..done + n].copy_from_slice(&bytes[..n]);
            done += n;
        }
        Ok(())
    }

    /// Reads the PCR `pcr` of the bank `alg`, as `tpm2_pcr_read` of Linux.
    ///
    /// # Errors
    ///
    /// The errors of `transmit`, and `EIO` for an error of the TPM or a response without the
    /// PCR.
    pub fn pcr_read(&self, alg: u16, pcr: u32) -> Result<Vec<u8>> {
        let (rc, rsp) = self.command(&cmd::pcr_read(alg, &[pcr]))?;
        if rc != cmd::RC_SUCCESS {
            return Err(Errno::EIO);
        }
        let (pcrs, digests) = cmd::parse_pcr_read(&rsp).ok_or(Errno::EIO)?;
        match (pcrs.as_slice(), digests.as_slice()) {
            ([p], [d]) if *p == pcr => Ok(d.to_vec()),
            _ => Err(Errno::EIO),
        }
    }

    /// Reads all of the PCRs of the bank `alg`, in the order of their numbers. Each command reads
    /// 8 PCRs, the most that a PC Client TPM reads in one command.
    ///
    /// # Errors
    ///
    /// The errors of `transmit`, and `EIO` for an error of the TPM or a response without the
    /// PCRs.
    pub fn pcr_read_bank(&self, alg: u16) -> Result<Vec<Vec<u8>>> {
        let all: Vec<u32> = (0..cmd::PCR_COUNT).collect();
        let mut out = Vec::with_capacity(all.len());
        for want in all.chunks(8) {
            let (rc, rsp) = self.command(&cmd::pcr_read(alg, want))?;
            if rc != cmd::RC_SUCCESS {
                return Err(Errno::EIO);
            }
            let (pcrs, digests) = cmd::parse_pcr_read(&rsp).ok_or(Errno::EIO)?;
            if pcrs != want {
                return Err(Errno::EIO);
            }
            out.extend(digests.iter().map(|d| d.to_vec()));
        }
        Ok(out)
    }
}

/// The TPM of the machine, after `init`.
static CHIP: SpinLock<Option<Arc<Chip>>> = SpinLock::new(None);

/// Gives the TPM of the machine, if `init` found one.
pub fn chip() -> Option<Arc<Chip>> {
    CHIP.lock().clone()
}

/// The clock of the kernel: the monotonic clock, and a sleep of one tick.
#[cfg(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64")))]
struct KernelClock;

#[cfg(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64")))]
impl Clock for KernelClock {
    fn now_ms(&self) -> u64 {
        rk_frame::time::nanos() / 1_000_000
    }

    fn sleep(&self) {
        static SLEEP: WaitQueue = WaitQueue::new();
        SLEEP.wait_until_timeout(rk_frame::time::ticks() + 1, || None::<()>);
    }
}

/// Finds the TPM of the machine, makes its driver, starts it and adds `/dev/tpm0` and
/// `/dev/tpmrm0`. Does nothing if there is no TPM or if it does not answer. A second call gives
/// the chip of the first. Gives the chip.
#[cfg(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64")))]
pub fn init() -> Option<Arc<Chip>> {
    use rk_frame::println;
    use rk_frame::tpm::Interface;

    if let Some(chip) = chip() {
        return Some(chip);
    }
    let dev = rk_frame::tpm::tpm()?;
    let Some(regs) = dev.map() else {
        println!("tpm: cannot map the registers at {:#x}", dev.phys());
        return None;
    };
    let transport: Result<Box<dyn Transport>> = match dev.interface() {
        Interface::Crb => crb::Crb::new(
            regs,
            dev.control_offset(),
            dev.phys(),
            |phys, len| dev.map_buffer(phys, len),
            &KernelClock,
        )
        .map(|c| Box::new(c) as Box<dyn Transport>),
        Interface::Tis => {
            tis::Tis::new(regs, &KernelClock).map(|t| Box::new(t) as Box<dyn Transport>)
        }
    };
    let name = match dev.interface() {
        Interface::Crb => "tpm_crb",
        Interface::Tis => "tpm_tis",
    };
    let transport = match transport {
        Ok(t) => t,
        Err(e) => {
            println!("{name}: no TPM at {:#x}, error {}", dev.phys(), e.get());
            return None;
        }
    };
    let chip = Chip::new(transport, Box::new(KernelClock));
    match chip.auto_startup() {
        Ok(started) => println!(
            "{name}: TPM 2.0 at {:#x}{}",
            dev.phys(),
            if started { ", TPM2_Startup sent" } else { "" }
        ),
        Err(e) => {
            println!("{name}: the TPM at {:#x} does not start, error {}", dev.phys(), e.get());
            return None;
        }
    }
    if let Err(e) = chip.read_cc_attrs() {
        println!("{name}: no attributes of the commands, error {}, so no /dev/tpmrm0", e.get());
    }
    let chip = Arc::new(chip);
    *CHIP.lock() = Some(chip.clone());
    dev::register(chip.clone());
    Some(chip)
}
