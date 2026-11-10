//! The TPM 2.0 commands that the kernel sends, and their durations, as tpm2-cmd.c of Linux.
//!
//! A command and a response start with a header of 10 bytes: the tag (2 bytes), the size of all
//! of the command or response (4 bytes), and the command code or the response code (4 bytes). All
//! numbers are big-endian.

use alloc::vec::Vec;

/// The size of the header of a command and of a response.
pub const HEADER_SIZE: usize = 10;
/// The largest command and response, as `TPM_BUFSIZE` of Linux.
pub const BUFSIZE: usize = 4096;

/// The tag of a command or response without sessions.
pub const ST_NO_SESSIONS: u16 = 0x8001;

/// The command code of `TPM2_SelfTest`.
pub const CC_SELF_TEST: u32 = 0x143;
/// The command code of `TPM2_Startup`.
pub const CC_STARTUP: u32 = 0x144;
/// The command code of `TPM2_GetCapability`.
pub const CC_GET_CAPABILITY: u32 = 0x17a;
/// The command code of `TPM2_GetRandom`.
pub const CC_GET_RANDOM: u32 = 0x17b;
/// The command code of `TPM2_PCR_Read`.
pub const CC_PCR_READ: u32 = 0x17e;

/// The response code of a command that the TPM did with no error.
pub const RC_SUCCESS: u32 = 0;
/// The TPM did not get `TPM2_Startup`, or it got it already.
pub const RC_INITIALIZE: u32 = 0x100;
/// The self test of the TPM runs.
pub const RC_TESTING: u32 = 0x90a;
/// The TPM is busy. Send the command again later.
pub const RC_RETRY: u32 = 0x922;

/// The startup type of `TPM2_Startup` after a reset.
pub const SU_CLEAR: u16 = 0;

/// The SHA-256 algorithm.
pub const ALG_SHA256: u16 = 0x000b;
/// The size of a SHA-256 digest.
pub const SHA256_SIZE: usize = 32;

/// The number of PCRs of a PC Client TPM.
pub const PCR_COUNT: u32 = 24;

/// The duration of a short command in milliseconds, as `TPM2_DURATION_SHORT` of Linux.
pub const DURATION_SHORT: u64 = 20;
/// The duration of a medium command, as `TPM2_DURATION_MEDIUM`.
pub const DURATION_MEDIUM: u64 = 750;
/// The duration of a long command, as `TPM2_DURATION_LONG`.
pub const DURATION_LONG: u64 = 2000;
/// The duration of a very long command, as `TPM2_DURATION_LONG_LONG`.
pub const DURATION_LONG_LONG: u64 = 300_000;
/// The duration of a command that has no duration of its own, as `TPM2_DURATION_DEFAULT`.
pub const DURATION_DEFAULT: u64 = 120_000;

/// Gives the time limit of the command with the code `cc` in milliseconds, as
/// `tpm2_calc_ordinal_duration` of Linux.
pub fn duration(cc: u32) -> u64 {
    match cc {
        // Startup, SequenceUpdate, SequenceComplete, EventSequenceComplete, HashSequenceStart,
        // PCR_Extend and GetCapability.
        0x144 | 0x15c | 0x13e | 0x185 | 0x186 | 0x182 | 0x17a => DURATION_MEDIUM,
        // SelfTest, GetRandom, HierarchyControl, HierarchyChangeAuth and NV_Read.
        0x143 | 0x17b | 0x121 | 0x129 | 0x14e => DURATION_LONG,
        // VerifySignature, CreatePrimary, Create and CreateLoaded.
        0x177 | 0x131 | 0x153 | 0x191 => DURATION_LONG_LONG,
        _ => DURATION_DEFAULT,
    }
}

/// Reads the big-endian `u16` at `at`.
pub fn be16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(b.get(at..at.checked_add(2)?)?.try_into().ok()?))
}

/// Reads the big-endian `u32` at `at`.
pub fn be32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(at..at.checked_add(4)?)?.try_into().ok()?))
}

/// The size field of the header of a command or response.
pub fn size(b: &[u8]) -> Option<usize> {
    be32(b, 2).map(|s| s as usize)
}

/// The command code of a command, or the response code of a response.
pub fn code(b: &[u8]) -> Option<u32> {
    be32(b, 6)
}

/// A command that is built from its fields.
struct Command(Vec<u8>);

impl Command {
    fn new(cc: u32) -> Self {
        let mut b = Vec::with_capacity(32);
        b.extend_from_slice(&ST_NO_SESSIONS.to_be_bytes());
        b.extend_from_slice(&0u32.to_be_bytes());
        b.extend_from_slice(&cc.to_be_bytes());
        Self(b)
    }

    fn u8(mut self, v: u8) -> Self {
        self.0.push(v);
        self
    }

    fn u16(mut self, v: u16) -> Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }

    fn u32(mut self, v: u32) -> Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }

    fn bytes(mut self, v: &[u8]) -> Self {
        self.0.extend_from_slice(v);
        self
    }

    fn finish(mut self) -> Vec<u8> {
        let len = (self.0.len() as u32).to_be_bytes();
        self.0[2..6].copy_from_slice(&len);
        self.0
    }
}

/// `TPM2_Startup` with the startup type `su`.
pub fn startup(su: u16) -> Vec<u8> {
    Command::new(CC_STARTUP).u16(su).finish()
}

/// `TPM2_SelfTest`. With `full`, the TPM tests all of its functions.
pub fn self_test(full: bool) -> Vec<u8> {
    Command::new(CC_SELF_TEST).u8(u8::from(full)).finish()
}

/// `TPM2_GetRandom` for `n` bytes.
pub fn get_random(n: u16) -> Vec<u8> {
    Command::new(CC_GET_RANDOM).u16(n).finish()
}

/// The bit map of `TPMS_PCR_SELECTION` for the PCRs `pcrs`: 3 bytes for 24 PCRs.
fn pcr_select(pcrs: &[u32]) -> [u8; 3] {
    let mut map = [0u8; 3];
    for &p in pcrs.iter().filter(|&&p| p < PCR_COUNT) {
        map[(p / 8) as usize] |= 1 << (p % 8);
    }
    map
}

/// `TPM2_PCR_Read` of the PCRs `pcrs` of the bank `alg`.
pub fn pcr_read(alg: u16, pcrs: &[u32]) -> Vec<u8> {
    Command::new(CC_PCR_READ).u32(1).u16(alg).u8(3).bytes(&pcr_select(pcrs)).finish()
}

/// Gives the random bytes of a response to `TPM2_GetRandom`: a `TPM2B_DIGEST` after the header.
pub fn parse_random(rsp: &[u8]) -> Option<&[u8]> {
    let n = usize::from(be16(rsp, HEADER_SIZE)?);
    rsp.get(HEADER_SIZE + 2..HEADER_SIZE + 2 + n)
}

/// Gives the digests of a response to `TPM2_PCR_Read`, in the order of the PCR numbers. After
/// the header come the update counter (4 bytes), the selection that the TPM read, and a
/// `TPML_DIGEST`. A TPM reads at most 8 PCRs in one command, so a selection of more PCRs gives a
/// part of them. The selection of the response tells which.
pub fn parse_pcr_read(rsp: &[u8]) -> Option<(Vec<u32>, Vec<&[u8]>)> {
    let mut at = HEADER_SIZE + 4;
    let count = be32(rsp, at)?;
    at += 4;
    let mut pcrs = Vec::new();
    for _ in 0..count {
        let _alg = be16(rsp, at)?;
        let n = usize::from(*rsp.get(at + 2)?);
        let map = rsp.get(at + 3..at + 3 + n)?;
        for (i, &byte) in map.iter().enumerate() {
            pcrs.extend((0..8).filter(|b| byte & (1 << b) != 0).map(|b| (i * 8 + b) as u32));
        }
        at += 3 + n;
    }
    let digests = be32(rsp, at)?;
    at += 4;
    let mut out = Vec::new();
    for _ in 0..digests {
        let n = usize::from(be16(rsp, at)?);
        out.push(rsp.get(at + 2..at + 2 + n)?);
        at += 2 + n;
    }
    (out.len() <= pcrs.len()).then(|| {
        pcrs.truncate(out.len());
        (pcrs, out)
    })
}
