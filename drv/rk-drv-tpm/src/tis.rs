//! The FIFO interface (TIS) of the TCG PC Client Platform TPM Profile, as tpm_tis_core.c of Linux.
//!
//! Each locality has 4 KiB of registers. The driver uses locality 0. A command takes the locality
//! with the access register, puts the TPM in the ready state, writes the command to the data FIFO
//! in bursts, and writes the go bit of the status register. The TPM sets the data available bit
//! when the response is ready, and the driver reads it from the data FIFO in bursts. The burst
//! count of the status register tells how many bytes the FIFO takes or gives at a time.

use crate::{Clock, Regs, Result, TIMEOUT_A, TIMEOUT_B, TIMEOUT_C, Transport, cmd, poll};
use rk_abi::Errno;

/// The registers of a locality.
const ACCESS: usize = 0x00;
const INT_ENABLE: usize = 0x08;
const STS: usize = 0x18;
const DATA_FIFO: usize = 0x24;
const DID_VID: usize = 0xf00;
const RID: usize = 0xf04;

/// The bits of `ACCESS`.
const ACCESS_VALID: u8 = 0x80;
const ACCESS_ACTIVE_LOCALITY: u8 = 0x20;
const ACCESS_REQUEST_USE: u8 = 0x02;

/// The bits of `STS`.
const STS_VALID: u8 = 0x80;
const STS_COMMAND_READY: u8 = 0x40;
const STS_GO: u8 = 0x20;
const STS_DATA_AVAIL: u8 = 0x10;
const STS_DATA_EXPECT: u8 = 0x08;

/// The bit of `INT_ENABLE` that turns on all of the interrupts.
const GLOBAL_INT_ENABLE: u32 = 1 << 31;

/// A TPM with the FIFO interface.
pub struct Tis<R: Regs> {
    regs: R,
    /// The locality of the commands.
    locality: usize,
    /// The vendor and device ID, and the revision.
    did_vid: u32,
    rid: u8,
}

impl<R: Regs> Tis<R> {
    /// Makes the driver of the TPM with the registers `regs`, as `tpm_tis_core_init` of Linux. It
    /// turns off the interrupts of the TPM, because the driver polls, and reads the IDs.
    ///
    /// # Errors
    ///
    /// `ENODEV` if no TPM answers, and `EBUSY` if the TPM does not give the locality.
    pub fn new(regs: R, clock: &dyn Clock) -> Result<Self> {
        let mut tis = Self { regs, locality: 0, did_vid: 0, rid: 0 };
        let did_vid = tis.regs.read_u32(tis.reg(DID_VID));
        if did_vid == 0 || did_vid == u32::MAX {
            return Err(Errno::ENODEV);
        }
        tis.request_locality(clock)?;
        let ints = tis.regs.read_u32(tis.reg(INT_ENABLE));
        tis.regs.write_u32(tis.reg(INT_ENABLE), ints & !GLOBAL_INT_ENABLE);
        tis.did_vid = did_vid;
        tis.rid = tis.regs.read_u8(tis.reg(RID));
        tis.release_locality();
        Ok(tis)
    }

    /// The vendor ID (bits 0 to 15) and the device ID (bits 16 to 31).
    pub fn did_vid(&self) -> u32 {
        self.did_vid
    }

    /// The revision ID.
    pub fn rid(&self) -> u8 {
        self.rid
    }

    /// The offset of the register `reg` of the locality of the driver.
    fn reg(&self, reg: usize) -> usize {
        self.locality << 12 | reg
    }

    fn status(&self) -> u8 {
        self.regs.read_u8(self.reg(STS))
    }

    /// Asks the TPM to go to the ready state, or cancels the command that runs.
    fn ready(&self) {
        self.regs.write_u8(self.reg(STS), STS_COMMAND_READY);
    }

    /// Tells if the driver has the locality, as `check_locality`.
    fn check_locality(&self) -> bool {
        let access = self.regs.read_u8(self.reg(ACCESS));
        access & (ACCESS_ACTIVE_LOCALITY | ACCESS_VALID | ACCESS_REQUEST_USE)
            == ACCESS_ACTIVE_LOCALITY | ACCESS_VALID
    }

    /// Asks for the locality and waits until the TPM gives it, as `__tpm_tis_request_locality`.
    fn request_locality(&self, clock: &dyn Clock) -> Result<()> {
        if self.check_locality() {
            return Ok(());
        }
        self.regs.write_u8(self.reg(ACCESS), ACCESS_REQUEST_USE);
        poll(clock, TIMEOUT_A, || self.check_locality()).map_err(|_| Errno::EBUSY)
    }

    /// Gives the locality back, as `tpm_tis_relinquish_locality`.
    fn release_locality(&self) {
        self.regs.write_u8(self.reg(ACCESS), ACCESS_ACTIVE_LOCALITY);
    }

    /// Waits until each bit of `mask` is set in the status, as `wait_for_tpm_stat`.
    fn wait_for_stat(&self, clock: &dyn Clock, mask: u8, ms: u64) -> Result<()> {
        poll(clock, ms, || self.status() & mask == mask)
    }

    /// Waits for a burst count that is not 0 and gives it, as `get_burstcount`. A TPM 2.0 has
    /// time limit A.
    fn burst_count(&self, clock: &dyn Clock) -> Result<usize> {
        let mut count = 0;
        poll(clock, TIMEOUT_A, || {
            count = (self.regs.read_u32(self.reg(STS)) >> 8 & 0xffff) as usize;
            count != 0
        })
        .map_err(|_| Errno::EBUSY)?;
        Ok(count)
    }

    /// Writes the command to the FIFO, as `tpm_tis_send_data`. The TPM must expect more data
    /// after each byte but the last, and no more after the last byte.
    fn send_data(&self, clock: &dyn Clock, cmd: &[u8]) -> Result<()> {
        if self.status() & STS_COMMAND_READY == 0 {
            self.ready();
            self.wait_for_stat(clock, STS_COMMAND_READY, TIMEOUT_B)?;
        }
        let Some((&last, head)) = cmd.split_last() else { return Err(Errno::EINVAL) };
        let mut sent = 0;
        while sent < head.len() {
            let burst = self.burst_count(clock)?.min(head.len() - sent);
            for &b in &head[sent..sent + burst] {
                self.regs.write_u8(self.reg(DATA_FIFO), b);
            }
            sent += burst;
            self.wait_for_stat(clock, STS_VALID, TIMEOUT_C)?;
            if self.status() & STS_DATA_EXPECT == 0 {
                return Err(Errno::EIO);
            }
        }
        self.regs.write_u8(self.reg(DATA_FIFO), last);
        self.wait_for_stat(clock, STS_VALID, TIMEOUT_C)?;
        if self.status() & STS_DATA_EXPECT != 0 {
            return Err(Errno::EIO);
        }
        Ok(())
    }

    /// Reads `buf.len()` bytes of the response from the FIFO, as `recv_data`. Gives the number of
    /// bytes that it read: less if the TPM has no more data in time.
    fn recv_data(&self, clock: &dyn Clock, buf: &mut [u8]) -> Result<usize> {
        let mut got = 0;
        while got < buf.len()
            && self.wait_for_stat(clock, STS_DATA_AVAIL | STS_VALID, TIMEOUT_C).is_ok()
        {
            let burst = self.burst_count(clock)?.min(buf.len() - got);
            for b in &mut buf[got..got + burst] {
                *b = self.regs.read_u8(self.reg(DATA_FIFO));
            }
            got += burst;
        }
        Ok(got)
    }

    /// Reads the response, as `tpm_tis_recv`: the header first, then the rest of the size that
    /// the header gives. The TPM must have no more data after it.
    fn recv(&self, clock: &dyn Clock, rsp: &mut [u8]) -> Result<usize> {
        if rsp.len() < cmd::HEADER_SIZE {
            return Err(Errno::EIO);
        }
        if self.recv_data(clock, &mut rsp[..cmd::HEADER_SIZE])? < cmd::HEADER_SIZE {
            return Err(Errno::EIO);
        }
        let len = cmd::size(rsp).ok_or(Errno::EIO)?;
        if len < cmd::HEADER_SIZE || len > rsp.len() {
            return Err(Errno::EIO);
        }
        let rest = self.recv_data(clock, &mut rsp[cmd::HEADER_SIZE..len])?;
        if cmd::HEADER_SIZE + rest < len {
            return Err(Errno::ETIME);
        }
        self.wait_for_stat(clock, STS_VALID, TIMEOUT_C)?;
        if self.status() & STS_DATA_AVAIL != 0 {
            return Err(Errno::EIO);
        }
        Ok(len)
    }

    /// Sends the command, starts it, waits for the response and reads it.
    fn send_recv(
        &self,
        clock: &dyn Clock,
        cmd: &[u8],
        rsp: &mut [u8],
        duration: u64,
    ) -> Result<usize> {
        self.send_data(clock, cmd)?;
        self.regs.write_u8(self.reg(STS), STS_GO);
        let mut status = 0;
        let done = poll(clock, duration, || {
            status = self.status();
            status & (STS_DATA_AVAIL | STS_VALID) == STS_DATA_AVAIL | STS_VALID
                || status == STS_COMMAND_READY
        });
        if done.is_err() {
            return Err(Errno::ETIME);
        }
        if status == STS_COMMAND_READY {
            return Err(Errno::ECANCELED);
        }
        self.recv(clock, rsp)
    }
}

impl<R: Regs> Transport for Tis<R> {
    fn transmit(
        &mut self,
        clock: &dyn Clock,
        cmd: &[u8],
        rsp: &mut [u8],
        duration: u64,
    ) -> Result<usize> {
        self.request_locality(clock)?;
        let result = self.send_recv(clock, cmd, rsp, duration);
        // The ready state ends the command, and cancels it after an error.
        self.ready();
        self.release_locality();
        result
    }

    fn name(&self) -> &'static str {
        "tpm_tis"
    }
}
