//! The event log of the firmware in securityfs, as drivers/char/tpm/eventlog of Linux.
//!
//! The firmware extends the PCRs while the machine boots, and it writes each measurement to a log.
//! rk-frame copies the log area: the area of the ACPI `TPM2` table on x86-64, and the area of
//! `linux,sml-base` on arm64. A log of TPM 2.0 has the crypto agile format of the TCG PC Client
//! Platform Firmware Profile. The first event has the SHA-1 format (`TCG_PCR_EVENT`) and holds
//! the `Spec ID Event03` structure, which gives the digest size of each algorithm. Each next event
//! (`TCG_PCR_EVENT2`) has a digest for each algorithm.
//!
//! [`register`] adds `/sys/kernel/security/tpm0/binary_bios_measurements`. The file has the
//! bytes of the events, as `tpm2_binary_bios_measurements_show` of Linux gives them: the first
//! event, and then each next event up to the first one that is not valid. Programs such as
//! `tpm2_eventlog` and `systemd-pcrlock` replay the events and compare the result with the PCRs.

use alloc::vec::Vec;
use rk_frame::sync::Once;
use rk_vfs::security::securityfs::{self, FileDef};

/// The type of an event that does not extend a PCR, `EV_NO_ACTION`.
pub const EV_NO_ACTION: u32 = 3;

/// The signature of the first event of a log in the crypto agile format, `TCG_SPECID_SIG` of
/// Linux with its NUL.
pub const SPEC_ID_SIGNATURE: &[u8; 16] = b"Spec ID Event03\0";

/// The path of the file in securityfs.
pub const PATH: &str = "tpm0/binary_bios_measurements";

/// The size of the first event without its data (`TCG_PCR_EVENT`): the PCR, the type, a SHA-1
/// digest and the size of the data.
const HEADER: usize = 32;
/// The offsets in the data of the first event (`TCG_EfiSpecIDEventStruct`) of the number of
/// algorithms and of their digest sizes.
const SPEC_NUM_ALGS: usize = 24;
const SPEC_DIGEST_SIZES: usize = 28;

/// Reads a little-endian `u32` of the log.
fn le32(log: &[u8], at: usize) -> Option<u32> {
    let b = log.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Reads a little-endian `u16` of the log.
fn le16(log: &[u8], at: usize) -> Option<u16> {
    let b = log.get(at..at.checked_add(2)?)?;
    Some(u16::from_le_bytes([b[0], b[1]]))
}

/// Tells if `log` starts with the first event of a log of TPM 2.0, as `tpm_is_tpm2_log` of Linux.
#[must_use]
pub fn is_tpm2_log(log: &[u8]) -> bool {
    log.get(HEADER..HEADER + SPEC_DIGEST_SIZES).is_some_and(|s| s.starts_with(SPEC_ID_SIGNATURE))
}

/// The size of the first event: its header and its data.
fn header_size(log: &[u8]) -> Option<usize> {
    HEADER.checked_add(le32(log, HEADER - 4)? as usize)
}

/// The size of the event at `at`, as `__calc_tpm2_event_size` of Linux. Gives 0 for an event
/// that is not valid: the first event of the log is not the `Spec ID Event03` event, the number
/// of digests is not the number of algorithms, a digest has an algorithm that the first event
/// does not give, or the type and the size of the data are 0. An event that goes past the end of
/// the log is also not valid.
fn event_size(log: &[u8], at: usize) -> usize {
    let size = || -> Option<usize> {
        if le32(log, 0)? != 0 || le32(log, 4)? != EV_NO_ACTION || log.get(8..28)? != [0; 20] {
            return None;
        }
        let spec = HEADER;
        if !is_tpm2_log(log) {
            return None;
        }
        let algs = le32(log, spec + SPEC_NUM_ALGS)?;
        let event_type = le32(log, at.checked_add(4)?)?;
        let count = le32(log, at.checked_add(8)?)?;
        if algs == 0 || count != algs {
            return None;
        }
        let mut p = at.checked_add(12)?;
        for _ in 0..count {
            let alg = le16(log, p)?;
            p = p.checked_add(2)?;
            let digest = (0..algs as usize).find_map(|j| {
                let entry = spec + SPEC_DIGEST_SIZES + 4 * j;
                (le16(log, entry)? == alg).then(|| le16(log, entry + 2)).flatten()
            })?;
            p = p.checked_add(usize::from(digest))?;
        }
        let data = le32(log, p)?;
        if event_type == 0 && data == 0 {
            return None;
        }
        let end = p.checked_add(4)?.checked_add(data as usize)?;
        (end <= log.len()).then(|| end - at)
    };
    size().unwrap_or(0)
}

/// Gives the bytes of `binary_bios_measurements` for the log area `log` and the number of
/// events in it, as the iteration of `tpm2_binary_b_measurements_seqops` of Linux. The first
/// event comes first. Then each next event comes, up to an event that is not valid or that
/// reaches the end of the area.
#[must_use]
pub fn measurements(log: &[u8]) -> (Vec<u8>, usize) {
    let limit = log.len();
    let Some(first) = header_size(log).filter(|&s| s < limit) else {
        return (Vec::new(), 0);
    };
    if le32(log, 4) == Some(0) && le32(log, HEADER - 4) == Some(0) {
        return (Vec::new(), 0);
    }
    let mut at = first;
    let mut count = 1;
    loop {
        let size = event_size(log, at);
        if size == 0 || at + size >= limit {
            break;
        }
        at += size;
        count += 1;
    }
    (log[..at].to_vec(), count)
}

/// The bytes of `binary_bios_measurements`, if the firmware gave a log.
static LOG: Once<Vec<u8>> = Once::new();

/// Gives the bytes of `binary_bios_measurements`, or `None` if there is no event log.
#[must_use]
pub fn binary_bios_measurements() -> Option<&'static [u8]> {
    LOG.get().map(Vec::as_slice)
}

/// Reads `binary_bios_measurements`.
fn read() -> Vec<u8> {
    binary_bios_measurements().map(<[u8]>::to_vec).unwrap_or_default()
}

/// Adds `/sys/kernel/security/tpm0/binary_bios_measurements` for the log area `log`, as
/// `tpm_bios_log_setup` of Linux. A log that does not have the format of TPM 2.0 gives no file,
/// as Linux. Gives the number of events in the file, or `None` if there is no file.
pub fn register(log: &[u8]) -> Option<usize> {
    if !is_tpm2_log(log) {
        return None;
    }
    let (bytes, count) = measurements(log);
    LOG.call_once(|| bytes);
    securityfs::create_file(FileDef { path: PATH, perm: 0o440, read, write: None });
    Some(count)
}
