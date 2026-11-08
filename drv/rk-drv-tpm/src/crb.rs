//! The command response buffer (CRB) interface, as tpm_crb.c of Linux.
//!
//! The registers of locality 0 start with the locality registers. The control area follows, and
//! the ACPI `TPM2` table gives its address. The control area gives the physical address and the
//! size of the command buffer and of the response buffer. QEMU puts the two buffers in the same
//! place, at offset 0x80 of the registers.
//!
//! A command takes the locality, asks the TPM to be ready, writes the command to the command
//! buffer and writes 1 to the start register. The TPM clears the start register when the response
//! is in the response buffer. Then the driver puts the TPM in the idle state and gives the
//! locality back.

use crate::{Clock, Regs, Result, TIMEOUT_C, Transport, cmd, poll};
use rk_abi::Errno;

/// The locality registers.
const LOC_STATE: usize = 0x00;
const LOC_CTRL: usize = 0x08;

/// The bits of `LOC_STATE`: the locality is assigned, and the registers are valid.
const LOC_STATE_ASSIGNED: u32 = 1 << 1;
const LOC_STATE_VALID: u32 = 1 << 7;
/// The bits of `LOC_CTRL`: ask for the locality, and give it back.
const LOC_CTRL_REQUEST: u32 = 1 << 0;
const LOC_CTRL_RELINQUISH: u32 = 1 << 1;

/// The registers of the control area, from its start.
const CTRL_REQ: usize = 0x00;
const CTRL_STS: usize = 0x04;
const CTRL_CANCEL: usize = 0x08;
const CTRL_START: usize = 0x0c;
const CTRL_CMD_SIZE: usize = 0x18;
const CTRL_CMD_LOW: usize = 0x1c;
const CTRL_CMD_HIGH: usize = 0x20;
const CTRL_RSP_SIZE: usize = 0x24;
const CTRL_RSP_ADDR: usize = 0x28;

/// The bits of `CTRL_REQ`: go to the ready state, and go to the idle state.
const REQ_CMD_READY: u32 = 1 << 0;
const REQ_GO_IDLE: u32 = 1 << 1;
/// The error bit of `CTRL_STS`.
const STS_ERROR: u32 = 1 << 0;
/// The bit of `CTRL_START` and of `CTRL_CANCEL`.
const INVOKE: u32 = 1 << 0;

/// The size of the start of a response that the driver reads first. It holds the size field.
const RSP_HEAD: usize = 8;

/// A buffer: at an offset of the registers, or in a mapping of its own.
enum Buffer<R> {
    InRegs(usize),
    Own(R),
}

/// A TPM with the CRB interface.
pub struct Crb<R: Regs> {
    regs: R,
    /// The offset of the control area in `regs`.
    ctrl: usize,
    cmd: Buffer<R>,
    cmd_len: usize,
    /// The response buffer. `None` is the command buffer.
    rsp: Option<Buffer<R>>,
    rsp_len: usize,
}

impl<R: Regs> Crb<R> {
    /// Makes the driver of the TPM with the registers `regs` at the physical address `phys`, and
    /// the control area at `ctrl` in them. It reads the places of the buffers, as `crb_map_io` of
    /// Linux. `map` maps a buffer that is not in the registers.
    ///
    /// # Errors
    ///
    /// `ETIME` if the TPM does not give the locality or does not get ready, `ENODEV` if the
    /// buffers are not valid, and `ENOMEM` if a buffer cannot be mapped.
    pub fn new(
        regs: R,
        ctrl: usize,
        phys: u64,
        mut map: impl FnMut(u64, usize) -> Option<R>,
        clock: &dyn Clock,
    ) -> Result<Self> {
        let mut crb =
            Self { regs, ctrl, cmd: Buffer::InRegs(0), cmd_len: 0, rsp: None, rsp_len: 0 };
        crb.request_locality(clock)?;
        let ready = crb.cmd_ready(clock);
        let cmd_pa =
            u64::from(crb.ctrl_read(CTRL_CMD_HIGH)) << 32 | u64::from(crb.ctrl_read(CTRL_CMD_LOW));
        let rsp_pa = u64::from(crb.ctrl_read(CTRL_RSP_ADDR + 4)) << 32
            | u64::from(crb.ctrl_read(CTRL_RSP_ADDR));
        let cmd_len = crb.ctrl_read(CTRL_CMD_SIZE) as usize;
        let rsp_len = crb.ctrl_read(CTRL_RSP_SIZE) as usize;
        let _ = crb.go_idle(clock);
        let _ = crb.relinquish_locality(clock);
        ready?;
        if cmd_pa == 0 || cmd_len < cmd::HEADER_SIZE || rsp_pa == 0 || rsp_len < cmd::HEADER_SIZE {
            return Err(Errno::ENODEV);
        }
        // The two buffers of the PTP specification are the same, or they do not overlap.
        if cmd_pa == rsp_pa && cmd_len != rsp_len {
            return Err(Errno::ENODEV);
        }
        let mut place = |pa: u64, len: usize| -> Result<Buffer<R>> {
            // The buffer is after the control area, in the registers.
            let after = (crb.ctrl + CTRL_RSP_ADDR + 8) as u64;
            match pa.checked_sub(phys) {
                Some(off) if off >= after && off + len as u64 <= crb.regs.size() as u64 => {
                    Ok(Buffer::InRegs(off as usize))
                }
                _ => map(pa, len).map(Buffer::Own).ok_or(Errno::ENOMEM),
            }
        };
        let cmd_buf = place(cmd_pa, cmd_len)?;
        let rsp_buf = if rsp_pa == cmd_pa { None } else { Some(place(rsp_pa, rsp_len)?) };
        crb.cmd = cmd_buf;
        crb.cmd_len = cmd_len.min(cmd::BUFSIZE);
        crb.rsp = rsp_buf;
        crb.rsp_len = rsp_len.min(cmd::BUFSIZE);
        Ok(crb)
    }

    fn ctrl_read(&self, reg: usize) -> u32 {
        self.regs.read_u32(self.ctrl + reg)
    }

    fn ctrl_write(&self, reg: usize, value: u32) {
        self.regs.write_u32(self.ctrl + reg, value);
    }

    /// Gives the registers of a buffer and the offset of the buffer in them.
    fn place<'a>(&'a self, b: &'a Buffer<R>) -> (&'a R, usize) {
        match b {
            Buffer::InRegs(off) => (&self.regs, *off),
            Buffer::Own(r) => (r, 0),
        }
    }

    /// Asks for locality 0 and waits until the TPM gives it, as `__crb_request_locality`.
    fn request_locality(&self, clock: &dyn Clock) -> Result<()> {
        self.regs.write_u32(LOC_CTRL, LOC_CTRL_REQUEST);
        let want = LOC_STATE_ASSIGNED | LOC_STATE_VALID;
        poll(clock, TIMEOUT_C, || self.regs.read_u32(LOC_STATE) & want == want)
    }

    /// Gives locality 0 back, as `__crb_relinquish_locality`.
    fn relinquish_locality(&self, clock: &dyn Clock) -> Result<()> {
        self.regs.write_u32(LOC_CTRL, LOC_CTRL_RELINQUISH);
        let mask = LOC_STATE_ASSIGNED | LOC_STATE_VALID;
        poll(clock, TIMEOUT_C, || self.regs.read_u32(LOC_STATE) & mask == LOC_STATE_VALID)
    }

    /// Asks the TPM to go to the ready state, as `__crb_cmd_ready`.
    fn cmd_ready(&self, clock: &dyn Clock) -> Result<()> {
        self.ctrl_write(CTRL_REQ, REQ_CMD_READY);
        poll(clock, TIMEOUT_C, || self.ctrl_read(CTRL_REQ) & REQ_CMD_READY == 0)
    }

    /// Asks the TPM to go to the idle state, as `__crb_go_idle`.
    fn go_idle(&self, clock: &dyn Clock) -> Result<()> {
        self.ctrl_write(CTRL_REQ, REQ_GO_IDLE);
        poll(clock, TIMEOUT_C, || self.ctrl_read(CTRL_REQ) & REQ_GO_IDLE == 0)
    }

    /// Sends `cmd` and reads the response, as `crb_send`, the wait of `tpm_try_transmit`, and
    /// `crb_recv`.
    fn send_recv(
        &self,
        clock: &dyn Clock,
        cmd: &[u8],
        rsp: &mut [u8],
        duration: u64,
    ) -> Result<usize> {
        if cmd.len() > self.cmd_len {
            return Err(Errno::E2BIG);
        }
        // A cancel of the last command must not cancel this one.
        self.ctrl_write(CTRL_CANCEL, 0);
        let (r, at) = self.place(&self.cmd);
        for (i, &b) in cmd.iter().enumerate() {
            r.write_u8(at + i, b);
        }
        self.ctrl_write(CTRL_START, INVOKE);
        let done = poll(clock, duration, || {
            self.ctrl_read(CTRL_START) & INVOKE == 0 || self.ctrl_read(CTRL_CANCEL) & INVOKE != 0
        });
        if done.is_err() {
            self.ctrl_write(CTRL_CANCEL, INVOKE);
            return Err(Errno::ETIME);
        }
        if self.ctrl_read(CTRL_START) & INVOKE != 0 {
            return Err(Errno::ECANCELED);
        }
        if rsp.len() < RSP_HEAD || self.ctrl_read(CTRL_STS) & STS_ERROR != 0 {
            return Err(Errno::EIO);
        }
        let (r, at) = self.place(self.rsp.as_ref().unwrap_or(&self.cmd));
        for (i, b) in rsp[..RSP_HEAD].iter_mut().enumerate() {
            *b = r.read_u8(at + i);
        }
        let len = cmd::size(rsp).ok_or(Errno::EIO)?;
        if len < RSP_HEAD || len > rsp.len() || len > self.rsp_len {
            return Err(Errno::EIO);
        }
        for (i, b) in rsp[RSP_HEAD..len].iter_mut().enumerate() {
            *b = r.read_u8(at + RSP_HEAD + i);
        }
        Ok(len)
    }
}

impl<R: Regs> Transport for Crb<R> {
    fn transmit(
        &mut self,
        clock: &dyn Clock,
        cmd: &[u8],
        rsp: &mut [u8],
        duration: u64,
    ) -> Result<usize> {
        self.request_locality(clock)?;
        let result = self.cmd_ready(clock).and_then(|()| self.send_recv(clock, cmd, rsp, duration));
        let _ = self.go_idle(clock);
        let _ = self.relinquish_locality(clock);
        result
    }

    fn name(&self) -> &'static str {
        "tpm_crb"
    }
}
