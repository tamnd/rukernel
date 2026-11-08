//! The tests of the driver, with a model of a TPM behind the CRB and the FIFO registers.

extern crate std;

use super::*;
use core::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// A clock that goes 1 ms forward at each sleep.
struct FakeClock(AtomicU64);

impl Clock for FakeClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
    fn sleep(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

fn clock() -> Box<dyn Clock> {
    Box::new(FakeClock(AtomicU64::new(0)))
}

/// The commands of a TPM: a TPM that needs `TPM2_Startup`, gives the bytes 0, 1, 2 and so on as
/// random bytes, and has the value `[n; 32]` in PCR `n` of the SHA-256 bank.
#[derive(Default)]
struct Logic {
    started: bool,
    /// The number of `TPM_RC_RETRY` answers before the next `TPM2_GetRandom` runs.
    retry: u32,
    /// The codes of the commands that came.
    seen: Vec<u32>,
}

fn response(rc: u32, body: &[u8]) -> Vec<u8> {
    let mut r = Vec::new();
    r.extend_from_slice(&cmd::ST_NO_SESSIONS.to_be_bytes());
    r.extend_from_slice(&((cmd::HEADER_SIZE + body.len()) as u32).to_be_bytes());
    r.extend_from_slice(&rc.to_be_bytes());
    r.extend_from_slice(body);
    r
}

impl Logic {
    fn answer(&mut self, c: &[u8]) -> Vec<u8> {
        let cc = cmd::code(c).unwrap();
        self.seen.push(cc);
        match cc {
            cmd::CC_SELF_TEST if self.started => response(cmd::RC_SUCCESS, &[]),
            cmd::CC_SELF_TEST | cmd::CC_STARTUP if !self.started => {
                self.started = cc == cmd::CC_STARTUP;
                response(if self.started { 0 } else { cmd::RC_INITIALIZE }, &[])
            }
            cmd::CC_STARTUP => response(cmd::RC_INITIALIZE, &[]),
            cmd::CC_GET_RANDOM if self.retry > 0 => {
                self.retry -= 1;
                response(cmd::RC_RETRY, &[])
            }
            cmd::CC_GET_RANDOM => {
                // This TPM gives at most 6 bytes at a time.
                let n = cmd::be16(c, 10).unwrap().min(6);
                let mut body = n.to_be_bytes().to_vec();
                body.extend((0..n).map(|i| i as u8));
                response(0, &body)
            }
            cmd::CC_PCR_READ => {
                let mut body = 7u32.to_be_bytes().to_vec();
                body.extend_from_slice(&c[10..20]);
                let pcrs: Vec<u32> =
                    (0..24u32).filter(|p| c[17 + *p as usize / 8] & (1 << (p % 8)) != 0).collect();
                body.extend_from_slice(&(pcrs.len() as u32).to_be_bytes());
                for p in pcrs {
                    body.extend_from_slice(&32u16.to_be_bytes());
                    body.extend_from_slice(&[p as u8; 32]);
                }
                response(0, &body)
            }
            _ => response(0x143, &[]),
        }
    }
}

/// The registers of the CRB of QEMU: locality 0, the control area at 0x40, and one buffer for
/// the command and the response at 0x80.
struct CrbModel {
    regs: [u32; 0x400],
    logic: Logic,
    /// The number of reads of the start register before the TPM clears it. `u32::MAX` never.
    busy_reads: u32,
}

#[derive(Clone)]
struct CrbRegs(Arc<Mutex<CrbModel>>);

const CRB_BUF: usize = 0x80;
const CRB_BUF_SIZE: u32 = 0xf80;

fn crb_model() -> CrbRegs {
    let mut m = CrbModel { regs: [0; 0x400], logic: Logic::default(), busy_reads: 3 };
    m.regs[0] = 1 << 7;
    m.regs[(0x40 + 0x18) / 4] = CRB_BUF_SIZE;
    m.regs[(0x40 + 0x1c) / 4] = 0xfed4_0000 + CRB_BUF as u32;
    m.regs[(0x40 + 0x24) / 4] = CRB_BUF_SIZE;
    m.regs[(0x40 + 0x28) / 4] = 0xfed4_0000 + CRB_BUF as u32;
    CrbRegs(Arc::new(Mutex::new(m)))
}

impl Regs for CrbRegs {
    fn size(&self) -> usize {
        0x1000
    }
    fn read_u8(&self, offset: usize) -> u8 {
        let m = self.0.lock().unwrap();
        m.regs[offset / 4].to_le_bytes()[offset % 4]
    }
    fn read_u32(&self, offset: usize) -> u32 {
        let mut m = self.0.lock().unwrap();
        if offset == 0x4c && m.regs[offset / 4] != 0 && m.busy_reads != u32::MAX {
            if m.busy_reads == 0 {
                let cmd: Vec<u8> = (0..CRB_BUF_SIZE as usize)
                    .map(|i| m.regs[(CRB_BUF + i) / 4].to_le_bytes()[i % 4])
                    .collect();
                let len = cmd::size(&cmd).unwrap();
                let rsp = m.logic.answer(&cmd[..len]);
                for (i, b) in rsp.into_iter().enumerate() {
                    let mut w = m.regs[(CRB_BUF + i) / 4].to_le_bytes();
                    w[i % 4] = b;
                    m.regs[(CRB_BUF + i) / 4] = u32::from_le_bytes(w);
                }
                m.regs[offset / 4] = 0;
                m.busy_reads = 3;
            } else {
                m.busy_reads -= 1;
            }
        }
        m.regs[offset / 4]
    }
    fn write_u8(&self, offset: usize, value: u8) {
        let mut m = self.0.lock().unwrap();
        let mut w = m.regs[offset / 4].to_le_bytes();
        w[offset % 4] = value;
        m.regs[offset / 4] = u32::from_le_bytes(w);
    }
    fn write_u32(&self, offset: usize, value: u32) {
        let mut m = self.0.lock().unwrap();
        match offset {
            // The locality: ask and give back.
            0x08 => m.regs[0] = if value & 1 != 0 { 1 << 7 | 1 << 1 } else { 1 << 7 },
            // Ready and idle are done at once.
            0x40 => m.regs[0x40 / 4] = 0,
            // A start without the locality does nothing, as in QEMU.
            0x4c if m.regs[0] & 1 << 1 == 0 => {}
            _ => m.regs[offset / 4] = value,
        }
    }
}

fn crb_chip(regs: CrbRegs) -> Chip {
    let c = FakeClock(AtomicU64::new(0));
    let crb = crb::Crb::new(regs, 0x40, 0xfed4_0000, |_, _| None, &c).unwrap();
    Chip::new(Box::new(crb), clock())
}

/// The status of the FIFO model.
#[derive(PartialEq)]
enum TisState {
    Idle,
    Ready,
    Reception,
    Execution,
    Completion,
}

struct TisModel {
    active: bool,
    state: TisState,
    input: Vec<u8>,
    output: Vec<u8>,
    burst: u32,
    int_enable: u32,
    logic: Logic,
}

#[derive(Clone)]
struct TisRegs(Arc<Mutex<TisModel>>);

fn tis_model() -> TisRegs {
    TisRegs(Arc::new(Mutex::new(TisModel {
        active: false,
        state: TisState::Idle,
        input: Vec::new(),
        output: Vec::new(),
        burst: 4,
        int_enable: 1 << 31,
        logic: Logic::default(),
    })))
}

impl TisModel {
    fn status(&self) -> u32 {
        let mut s = 0x80;
        match self.state {
            TisState::Ready => s |= 0x40,
            TisState::Reception => {
                let want = cmd::size(&self.input).unwrap_or(usize::MAX);
                if self.input.len() < want {
                    s |= 0x08;
                }
            }
            TisState::Completion if !self.output.is_empty() => s |= 0x10,
            _ => {}
        }
        s | self.burst << 8
    }
}

impl Regs for TisRegs {
    fn size(&self) -> usize {
        0x5000
    }
    fn read_u8(&self, offset: usize) -> u8 {
        let mut m = self.0.lock().unwrap();
        match offset {
            0x00 => 0x80 | if m.active { 0x20 } else { 0 },
            0x18 => m.status() as u8,
            0x24 if m.state == TisState::Completion && !m.output.is_empty() => m.output.remove(0),
            0xf04 => 1,
            _ => 0xff,
        }
    }
    fn read_u32(&self, offset: usize) -> u32 {
        let m = self.0.lock().unwrap();
        match offset {
            0x08 => m.int_enable,
            0x18 => m.status(),
            0xf00 => 0x0001_1014,
            _ => u32::MAX,
        }
    }
    fn write_u8(&self, offset: usize, value: u8) {
        let mut m = self.0.lock().unwrap();
        match (offset, value) {
            (0x00, 0x02) => m.active = true,
            (0x00, 0x20) => m.active = false,
            (0x18, 0x40) => {
                m.state = TisState::Ready;
                m.input.clear();
                m.output.clear();
            }
            (0x18, 0x20) if m.state == TisState::Reception => {
                m.state = TisState::Execution;
                let input = core::mem::take(&mut m.input);
                m.output = m.logic.answer(&input);
                m.state = TisState::Completion;
            }
            (0x24, b) if matches!(m.state, TisState::Ready | TisState::Reception) => {
                m.state = TisState::Reception;
                m.input.push(b);
            }
            _ => {}
        }
    }
    fn write_u32(&self, offset: usize, value: u32) {
        let mut m = self.0.lock().unwrap();
        if offset == 0x08 {
            m.int_enable = value;
        }
    }
}

fn tis_chip(regs: TisRegs) -> Chip {
    let c = FakeClock(AtomicU64::new(0));
    let tis = tis::Tis::new(regs, &c).unwrap();
    assert_eq!(tis.did_vid(), 0x0001_1014);
    assert_eq!(tis.rid(), 1);
    Chip::new(Box::new(tis), clock())
}

/// The three commands of the boot test: the startup, random bytes, and two PCRs.
fn startup_random_pcrs(chip: &Chip) {
    assert_eq!(chip.auto_startup(), Ok(true));
    assert_eq!(chip.auto_startup(), Ok(false));
    assert_eq!(chip.startup(), Ok(cmd::RC_INITIALIZE));
    let mut r = [0xaa; 8];
    chip.get_random(&mut r).unwrap();
    assert_eq!(r, [0, 1, 2, 3, 4, 5, 0, 1]);
    assert_eq!(chip.pcr_read(cmd::ALG_SHA256, 7).unwrap(), [7; 32]);
    assert_eq!(chip.pcr_read(cmd::ALG_SHA256, 0).unwrap(), [0; 32]);
}

#[test]
fn builds_the_commands() {
    assert_eq!(cmd::startup(cmd::SU_CLEAR), [0x80, 1, 0, 0, 0, 12, 0, 0, 1, 0x44, 0, 0]);
    assert_eq!(cmd::self_test(true), [0x80, 1, 0, 0, 0, 11, 0, 0, 1, 0x43, 1]);
    assert_eq!(cmd::get_random(8), [0x80, 1, 0, 0, 0, 12, 0, 0, 1, 0x7b, 0, 8]);
    assert_eq!(
        cmd::pcr_read(cmd::ALG_SHA256, &[0, 7, 23]),
        [0x80, 1, 0, 0, 0, 20, 0, 0, 1, 0x7e, 0, 0, 0, 1, 0, 0x0b, 3, 0x81, 0, 0x80]
    );
    assert_eq!(cmd::duration(cmd::CC_STARTUP), cmd::DURATION_MEDIUM);
    assert_eq!(cmd::duration(cmd::CC_GET_RANDOM), cmd::DURATION_LONG);
    assert_eq!(cmd::duration(0x131), cmd::DURATION_LONG_LONG);
    assert_eq!(cmd::duration(0x999), cmd::DURATION_DEFAULT);
}

#[test]
fn parses_a_pcr_read_response() {
    let mut l = Logic::default();
    let rsp = l.answer(&cmd::pcr_read(cmd::ALG_SHA256, &[0, 7]));
    let (pcrs, digests) = cmd::parse_pcr_read(&rsp).unwrap();
    assert_eq!(pcrs, [0, 7]);
    assert_eq!(digests, [&[0u8; 32][..], &[7u8; 32][..]]);
    assert_eq!(cmd::parse_pcr_read(&rsp[..rsp.len() - 1]), None);
}

#[test]
fn crb_sends_the_commands() {
    let regs = crb_model();
    let chip = crb_chip(regs.clone());
    assert_eq!(chip.name(), "tpm_crb");
    startup_random_pcrs(&chip);
    let m = regs.0.lock().unwrap();
    // The TPM is idle and the locality is free after each command.
    assert_eq!(m.regs[0], 1 << 7);
    assert_eq!(m.logic.seen[..3], [cmd::CC_SELF_TEST, cmd::CC_STARTUP, cmd::CC_SELF_TEST]);
}

#[test]
fn crb_cancels_a_command_after_its_duration() {
    let regs = crb_model();
    let chip = crb_chip(regs.clone());
    regs.0.lock().unwrap().busy_reads = u32::MAX;
    assert_eq!(chip.command(&cmd::startup(cmd::SU_CLEAR)), Err(Errno::ETIME));
    assert_eq!(regs.0.lock().unwrap().regs[0x48 / 4], 1);
}

#[test]
fn crb_buffers_outside_the_registers_are_mapped() {
    let regs = crb_model();
    regs.0.lock().unwrap().regs[(0x40 + 0x28) / 4] = 0x8000_0000;
    let c = FakeClock(AtomicU64::new(0));
    let mut asked = Vec::new();
    let r = crb::Crb::new(
        regs,
        0x40,
        0xfed4_0000,
        |pa, len| {
            asked.push((pa, len));
            None
        },
        &c,
    );
    assert!(matches!(r, Err(Errno::ENOMEM)));
    assert_eq!(asked, [(0x8000_0000, CRB_BUF_SIZE as usize)]);
}

#[test]
fn tis_sends_the_commands() {
    let regs = tis_model();
    let chip = tis_chip(regs.clone());
    assert_eq!(chip.name(), "tpm_tis");
    startup_random_pcrs(&chip);
    let m = regs.0.lock().unwrap();
    assert!(!m.active);
    assert_eq!(m.int_enable, 0);
    assert!(m.state == TisState::Ready);
}

#[test]
fn tis_sends_with_a_burst_of_one() {
    let regs = tis_model();
    regs.0.lock().unwrap().burst = 1;
    startup_random_pcrs(&tis_chip(regs));
}

#[test]
fn a_missing_tis_is_no_device() {
    #[derive(Clone)]
    struct Nothing;
    impl Regs for Nothing {
        fn size(&self) -> usize {
            0x5000
        }
        fn read_u8(&self, _: usize) -> u8 {
            0xff
        }
        fn read_u32(&self, _: usize) -> u32 {
            u32::MAX
        }
        fn write_u8(&self, _: usize, _: u8) {}
        fn write_u32(&self, _: usize, _: u32) {}
    }
    let c = FakeClock(AtomicU64::new(0));
    assert!(matches!(tis::Tis::new(Nothing, &c), Err(Errno::ENODEV)));
}

#[test]
fn retries_a_busy_tpm() {
    let regs = tis_model();
    let chip = tis_chip(regs.clone());
    chip.auto_startup().unwrap();
    regs.0.lock().unwrap().logic.retry = 2;
    let mut r = [0; 4];
    chip.get_random(&mut r).unwrap();
    assert_eq!(r, [0, 1, 2, 3]);
    // A TPM that stays busy gives its answer after the long duration.
    regs.0.lock().unwrap().logic.retry = 100;
    let (rc, _) = chip.command(&cmd::get_random(4)).unwrap();
    assert_eq!(rc, cmd::RC_RETRY);
}

#[test]
fn rejects_a_bad_command() {
    let chip = tis_chip(tis_model());
    assert_eq!(chip.command(&[0x80, 1, 0, 0]), Err(Errno::EINVAL));
    let mut c = cmd::startup(cmd::SU_CLEAR);
    c[5] = 13;
    assert_eq!(chip.command(&c), Err(Errno::E2BIG));
}
