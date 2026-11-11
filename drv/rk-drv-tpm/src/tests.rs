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

#[test]
fn reads_all_of_a_pcr_bank() {
    let chip = crb_chip(crb_model());
    chip.auto_startup().unwrap();
    let bank = chip.pcr_read_bank(cmd::ALG_SHA256).unwrap();
    assert_eq!(bank.len(), 24);
    assert!(bank.iter().enumerate().all(|(i, d)| *d == [i as u8; 32]));
}

#[test]
fn the_device_sends_one_command_at_a_time() {
    use rk_vfs::device::CharDevice;
    use rk_vfs::file::File;

    let chip = Arc::new(crb_chip(crb_model()));
    chip.auto_startup().unwrap();
    let device = dev::TpmDevice::new(chip.clone());
    let ops = device.open(0).unwrap();
    assert_eq!(device.open(0).err(), Some(Errno::EBUSY));
    let file = File::with_ops(ops.clone(), None, 2);
    let pollin = rk_abi::native::poll::POLLIN;
    assert_eq!(ops.poll(&file) & pollin, 0);
    let c = cmd::get_random(4);
    assert_eq!(ops.write(&file, &c), Ok(c.len()));
    assert_ne!(ops.poll(&file) & pollin, 0);
    // A second command must wait for the read of the response.
    assert_eq!(ops.write(&file, &c), Err(Errno::EBUSY));
    let mut head = [0u8; 4];
    assert_eq!(ops.read(&file, &mut head), Ok(4));
    let mut rest = [0u8; 64];
    assert_eq!(ops.read(&file, &mut rest), Ok(12));
    assert_eq!(head, [0x80, 1, 0, 0]);
    assert_eq!(rest[..12], [0, 16, 0, 0, 0, 0, 0, 4, 0, 1, 2, 3]);
    assert_eq!(ops.read(&file, &mut rest), Ok(0));
    // A write after a read of a part of the response drops the rest, as Linux.
    assert_eq!(ops.write(&file, &c), Ok(c.len()));
    assert_eq!(ops.read(&file, &mut head), Ok(4));
    assert_eq!(ops.write(&file, &c), Ok(c.len()));
    assert_eq!(ops.read(&file, &mut rest), Ok(16));
    assert_eq!(ops.write(&file, &[0u8; 4]), Err(Errno::EINVAL));
    // The size field must not be larger than the write.
    let mut long = c.clone();
    long[5] += 1;
    assert_eq!(ops.write(&file, &long), Err(Errno::EINVAL));
    // Linux sends the bytes of the size field, and drops the bytes after them.
    long[5] -= 1;
    long.push(0);
    assert_eq!(ops.write(&file, &long), Ok(long.len()));
    assert_eq!(ops.read(&file, &mut rest), Ok(16));
    assert_eq!(ops.write(&file, &[0u8; cmd::BUFSIZE + 1]), Err(Errno::E2BIG));
    drop(file);
    drop(ops);
    assert!(device.open(0).is_ok());
}

#[test]
fn the_sysfs_files_have_the_pcrs() {
    use alloc::string::String;

    let chip = crb_chip(crb_model());
    chip.auto_startup().unwrap();
    let names = |rest: &[&str]| -> Vec<String> {
        dev::sysfs(&chip, rest).unwrap().into_iter().map(|(n, _)| n).collect()
    };
    assert_eq!(names(&[]), ["pcr-sha256", "tpm_version_major"]);
    let pcrs = dev::sysfs(&chip, &["pcr-sha256"]).unwrap();
    assert_eq!(pcrs.len(), 24);
    assert_eq!(pcrs[10].0, "10");
    let want = alloc::format!("{}\n", "0A".repeat(32));
    assert_eq!(pcrs[10].1, rk_vfs::input::SysEntry::File(want.into_bytes()));
    assert!(dev::sysfs(&chip, &["pcr-sha1"]).is_none());
}

/// A model of a TPM for the resource manager: it makes objects and sessions, and saves, loads
/// and flushes their contexts. It gives the attributes of at most 2 commands in a response to
/// `TPM2_GetCapability`, so that the driver must ask more than once.
#[derive(Default)]
struct SpaceModel {
    /// The loaded objects: the handle and the number of the object.
    objects: Vec<(u32, u32)>,
    /// The sessions, and whether each one is loaded.
    sessions: Vec<(u32, bool)>,
    next: u32,
    /// The codes of the commands that came.
    seen: Vec<u32>,
}

const CC_CREATE_PRIMARY: u32 = 0x131;
const CC_START_AUTH_SESSION: u32 = 0x176;

/// The attributes of the commands of the model, as TPM2_GetCapability gives them: the number of
/// handles at bit 25, and the bit 28 for a handle in the response.
const MODEL_ATTRS: [u32; 6] = [
    CC_CREATE_PRIMARY | 1 << 25 | 1 << 28,
    cmd::CC_CONTEXT_LOAD | 1 << 28,
    cmd::CC_CONTEXT_SAVE | 1 << 25,
    cmd::CC_FLUSH_CONTEXT,
    CC_START_AUTH_SESSION | 2 << 25 | 1 << 28,
    cmd::CC_GET_CAPABILITY,
];

impl SpaceModel {
    fn answer(&mut self, c: &[u8]) -> Vec<u8> {
        let cc = cmd::code(c).unwrap();
        self.seen.push(cc);
        let h = cmd::be32(c, 10).unwrap_or(0);
        match cc {
            CC_CREATE_PRIMARY => {
                self.next += 1;
                let handle = (0x8000_0000..).find(|h| self.objects.iter().all(|o| o.0 != *h));
                self.objects.push((handle.unwrap(), self.next));
                response(0, &handle.unwrap().to_be_bytes())
            }
            CC_START_AUTH_SESSION => {
                self.next += 1;
                let handle = 0x0200_0000 + self.next;
                self.sessions.push((handle, true));
                response(0, &handle.to_be_bytes())
            }
            cmd::CC_CONTEXT_SAVE => {
                let mut ctx = 7u64.to_be_bytes().to_vec();
                ctx.extend_from_slice(&h.to_be_bytes());
                ctx.extend_from_slice(&0x4000_0001u32.to_be_bytes());
                if let Some(o) = self.objects.iter().find(|o| o.0 == h) {
                    ctx.extend_from_slice(&4u16.to_be_bytes());
                    ctx.extend_from_slice(&o.1.to_be_bytes());
                } else if let Some(s) = self.sessions.iter_mut().find(|s| s.0 == h && s.1) {
                    s.1 = false;
                    ctx.extend_from_slice(&0u16.to_be_bytes());
                } else {
                    return response(cmd::RC_REFERENCE_H0, &[]);
                }
                response(0, &ctx)
            }
            cmd::CC_CONTEXT_LOAD => {
                let saved = cmd::be32(c, 18).unwrap();
                if saved & 0xff00_0000 == cmd::HT_TRANSIENT {
                    let id = cmd::be32(c, 28).unwrap();
                    let handle = (0x8000_0000..).find(|h| self.objects.iter().all(|o| o.0 != *h));
                    self.objects.push((handle.unwrap(), id));
                    return response(0, &handle.unwrap().to_be_bytes());
                }
                match self.sessions.iter_mut().find(|s| s.0 == saved && !s.1) {
                    Some(s) => {
                        s.1 = true;
                        response(0, &saved.to_be_bytes())
                    }
                    None => response(cmd::RC_HANDLE | 0x100 | 0x40, &[]),
                }
            }
            cmd::CC_FLUSH_CONTEXT => {
                let (o, s) = (self.objects.len(), self.sessions.len());
                self.objects.retain(|x| x.0 != h);
                self.sessions.retain(|x| x.0 != h);
                if (o, s) == (self.objects.len(), self.sessions.len()) {
                    return response(cmd::RC_HANDLE | 0x100 | 0x40, &[]);
                }
                response(0, &[])
            }
            cmd::CC_GET_CAPABILITY => {
                let cap = cmd::be32(c, 10).unwrap();
                let from = cmd::be32(c, 14).unwrap();
                let values: Vec<u32> = if cap == cmd::CAP_COMMANDS {
                    MODEL_ATTRS.iter().copied().filter(|a| a & 0xffff >= from).collect()
                } else {
                    let mut all: Vec<u32> = self.objects.iter().map(|o| o.0).collect();
                    all.extend(self.sessions.iter().map(|s| s.0));
                    all.into_iter().filter(|&h| h >= from).collect()
                };
                let n = if cap == cmd::CAP_COMMANDS { values.len().min(2) } else { values.len() };
                let mut body = vec![u8::from(n < values.len())];
                body.extend_from_slice(&cap.to_be_bytes());
                body.extend_from_slice(&(n as u32).to_be_bytes());
                for v in &values[..n] {
                    body.extend_from_slice(&v.to_be_bytes());
                }
                response(0, &body)
            }
            _ => response(cmd::RC_COMMAND_CODE, &[]),
        }
    }
}

/// The interface of `SpaceModel`.
struct SpaceTransport(Arc<Mutex<SpaceModel>>);

impl Transport for SpaceTransport {
    fn transmit(&mut self, _: &dyn Clock, c: &[u8], rsp: &mut [u8], _: u64) -> Result<usize> {
        let r = self.0.lock().unwrap().answer(c);
        rsp[..r.len()].copy_from_slice(&r);
        Ok(r.len())
    }

    fn name(&self) -> &'static str {
        "model"
    }
}

fn space_chip() -> (Arc<Mutex<SpaceModel>>, Chip) {
    let model = Arc::new(Mutex::new(SpaceModel::default()));
    let chip = Chip::new(Box::new(SpaceTransport(model.clone())), clock());
    (model, chip)
}

/// A command with the code `cc` and the handles `handles`.
fn with_handles(cc: u32, handles: &[u32]) -> Vec<u8> {
    let mut c = response(cc, &[]);
    for h in handles {
        c.extend_from_slice(&h.to_be_bytes());
    }
    let len = c.len() as u32;
    c[2..6].copy_from_slice(&len.to_be_bytes());
    c
}

/// The transient handles that `TPM2_GetCapability` gives in the space `s`.
fn space_handles(chip: &Chip, s: &mut space::Space) -> Vec<u32> {
    let c = cmd::get_capability(cmd::CAP_HANDLES, cmd::HT_TRANSIENT, 16);
    let r = space::transmit(&mut chip.lock(), s, &c).unwrap();
    let (more, handles) = cmd::parse_capability_u32(&r, cmd::CAP_HANDLES).unwrap();
    assert!(!more);
    assert_eq!(cmd::size(&r), Some(r.len()));
    handles
}

#[test]
fn reads_the_attributes_of_the_commands() {
    let (model, chip) = space_chip();
    assert!(!chip.has_cc_attrs());
    chip.read_cc_attrs().unwrap();
    assert_eq!(model.lock().unwrap().seen, [cmd::CC_GET_CAPABILITY; 3]);
    assert_eq!(chip.cc_attrs(CC_CREATE_PRIMARY), Some(MODEL_ATTRS[0]));
    // The flush and the save get one handle.
    assert_eq!(chip.cc_attrs(cmd::CC_FLUSH_CONTEXT), Some(cmd::CC_FLUSH_CONTEXT | 1 << 25));
    assert_eq!(chip.cc_attrs(cmd::CC_CONTEXT_SAVE), Some(cmd::CC_CONTEXT_SAVE | 1 << 25));
    assert_eq!(chip.cc_attrs(cmd::CC_GET_RANDOM), None);
    assert_eq!(chip.cc_attrs(CC_CREATE_PRIMARY | 1 << 29), None);
}

#[test]
fn two_spaces_do_not_see_their_objects() {
    let (model, chip) = space_chip();
    chip.read_cc_attrs().unwrap();
    let (mut a, mut b) = (space::Space::new(), space::Space::new());
    let create = with_handles(CC_CREATE_PRIMARY, &[0x4000_0001]);
    let create_in = |s: &mut space::Space| {
        let r = space::transmit(&mut chip.lock(), s, &create).unwrap();
        assert_eq!(cmd::code(&r), Some(0));
        assert_eq!(cmd::be32(&r, 10).unwrap() & 0xff00_0000, cmd::HT_TRANSIENT);
    };
    create_in(&mut a);
    create_in(&mut b);
    create_in(&mut a);
    // Between the commands, the TPM has no objects of the spaces.
    assert!(model.lock().unwrap().objects.is_empty());
    assert_eq!(space_handles(&chip, &mut a), [0x80ff_ffff, 0x80ff_fffe]);
    assert_eq!(space_handles(&chip, &mut b), [0x80ff_ffff]);
    // A flush of a virtual handle flushes the object of the space.
    let flush = cmd::flush_context(0x80ff_ffff);
    let r = space::transmit(&mut chip.lock(), &mut a, &flush).unwrap();
    assert_eq!(cmd::code(&r), Some(0));
    assert_eq!(space_handles(&chip, &mut a), [0x80ff_fffe]);
    assert_eq!(space_handles(&chip, &mut b), [0x80ff_ffff]);
    // A handle that is not in the space gives EINVAL, and the space does not change.
    let r = space::transmit(&mut chip.lock(), &mut a, &cmd::flush_context(0x8012_3456));
    assert_eq!(r, Err(Errno::EINVAL));
    assert_eq!(space_handles(&chip, &mut a), [0x80ff_fffe]);
    assert!(model.lock().unwrap().objects.is_empty());
}

#[test]
fn a_full_space_flushes_the_new_object() {
    let (model, chip) = space_chip();
    chip.read_cc_attrs().unwrap();
    let mut a = space::Space::new();
    let create = with_handles(CC_CREATE_PRIMARY, &[0x4000_0001]);
    for _ in 0..space::SLOTS {
        space::transmit(&mut chip.lock(), &mut a, &create).unwrap();
    }
    assert_eq!(space::transmit(&mut chip.lock(), &mut a, &create), Err(Errno::ENOMEM));
    assert!(model.lock().unwrap().objects.is_empty());
    assert_eq!(space_handles(&chip, &mut a).len(), space::SLOTS);
}

#[test]
fn a_command_that_the_tpm_does_not_have_gets_the_layer_of_the_resource_manager() {
    let (model, chip) = space_chip();
    chip.read_cc_attrs().unwrap();
    let mut a = space::Space::new();
    let r = space::transmit(&mut chip.lock(), &mut a, &cmd::get_random(8)).unwrap();
    assert_eq!(cmd::code(&r), Some(cmd::RC_COMMAND_CODE | cmd::RC_RESMGR_LAYER));
    assert_eq!(r.len(), 10);
    assert_eq!(model.lock().unwrap().seen.len(), 3);
    // A command that is shorter than its handles is not correct.
    let short = with_handles(CC_START_AUTH_SESSION, &[0x4000_0007]);
    assert_eq!(space::transmit(&mut chip.lock(), &mut a, &short), Err(Errno::EINVAL));
    // Without the attributes, the resource manager does not send commands.
    let (_, bare) = space_chip();
    assert_eq!(space::transmit(&mut bare.lock(), &mut a, &short), Err(Errno::EINVAL));
}

#[test]
fn sessions_stay_saved_and_go_when_the_file_closes() {
    use rk_vfs::device::CharDevice;
    use rk_vfs::file::File;

    let (model, chip) = space_chip();
    chip.read_cc_attrs().unwrap();
    let chip = Arc::new(chip);
    let device = dev::TpmrmDevice::new(chip.clone());
    let ops = device.open(0).unwrap();
    // Many files of /dev/tpmrm0 can be open.
    let other = device.open(0).unwrap();
    let file = File::with_ops(ops.clone(), None, 2);
    let c = with_handles(CC_START_AUTH_SESSION, &[0x4000_0007, 0x4000_0007]);
    assert_eq!(ops.write(&file, &c), Ok(c.len()));
    let mut r = [0u8; 64];
    assert_eq!(ops.read(&file, &mut r), Ok(14));
    let session = cmd::be32(&r, 10).unwrap();
    assert_eq!(session & 0xff00_0000, cmd::HT_HMAC_SESSION);
    // The TPM keeps the session, but it is not loaded between the commands.
    assert_eq!(model.lock().unwrap().sessions, [(session, false)]);
    let cap = cmd::get_capability(cmd::CAP_HANDLES, 0, 16);
    assert_eq!(ops.write(&file, &cap), Ok(cap.len()));
    let n = ops.read(&file, &mut r).unwrap();
    assert_eq!(cmd::parse_capability_u32(&r[..n], cmd::CAP_HANDLES).unwrap().1, [session]);
    assert_eq!(model.lock().unwrap().sessions, [(session, false)]);
    // An error of a nonblocking write comes in the next read.
    let nonblock = File::with_ops(other.clone(), None, 2 | rk_abi::native::open::O_NONBLOCK);
    let bad = cmd::flush_context(0x8012_3456);
    assert_eq!(other.write(&nonblock, &bad), Ok(bad.len()));
    assert_ne!(other.poll(&nonblock) & rk_abi::native::poll::POLLIN, 0);
    assert_eq!(other.read(&nonblock, &mut r), Err(Errno::EINVAL));
    assert_eq!(other.read(&nonblock, &mut r), Ok(0));
    assert_eq!(other.write(&file, &bad), Err(Errno::EINVAL));
    drop(file);
    drop(ops);
    assert!(model.lock().unwrap().sessions.is_empty());
    assert_eq!(model.lock().unwrap().seen.last(), Some(&cmd::CC_FLUSH_CONTEXT));
}
