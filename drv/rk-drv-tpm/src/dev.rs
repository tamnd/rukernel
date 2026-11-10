//! `/dev/tpm0` and `/sys/class/tpm/tpm0`, as tpm-dev.c, tpm-dev-common.c and tpm-sysfs.c of
//! Linux.
//!
//! One file of `/dev/tpm0` can be open at a time. A second open gives `EBUSY`. A write sends one
//! command to the TPM and keeps the response. A read gives the response, and a part of it if the
//! buffer is small. The next write must come after the read of all of the response, else it gives
//! `EBUSY`. `poll` tells that a read can come when the file has a response, and that a write can
//! come when it does not.
//!
//! The directory of the device in sysfs has `tpm_version_major`, and `pcr-sha256` with a file for
//! each PCR of the SHA-256 bank. Each file has the digest in hexadecimal, as Linux shows it.

use crate::{Chip, cmd};
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Write;
use core::sync::atomic::{AtomicBool, Ordering};
use rk_abi::Errno;
use rk_abi::native::poll::{POLLIN, POLLOUT, POLLRDNORM, POLLWRNORM};
use rk_frame::sync::SpinLock;
use rk_vfs::device::{CharDevice, DeviceInfo, makedev};
use rk_vfs::inode::Result;
use rk_vfs::input::SysEntry;
use rk_vfs::{File, FileOps};

/// The major number of the misc devices, `MISC_MAJOR` of Linux.
pub const MISC_MAJOR: u32 = 10;
/// The minor number of `/dev/tpm0`, `TPM_MINOR` of Linux.
pub const TPM_MINOR: u32 = 224;
/// The device number of `/dev/tpm0`.
pub const TPM0_RDEV: u64 = makedev(MISC_MAJOR, TPM_MINOR);

/// The class of the TPM devices in sysfs.
pub const CLASS: &str = "tpm";

/// The driver of `/dev/tpm0`.
pub struct TpmDevice {
    chip: Arc<Chip>,
    /// Tells if a file of the device is open, as `is_open` of Linux.
    open: Arc<AtomicBool>,
}

impl TpmDevice {
    /// Makes the driver of the device of `chip`.
    pub fn new(chip: Arc<Chip>) -> Self {
        Self { chip, open: Arc::new(AtomicBool::new(false)) }
    }
}

impl CharDevice for TpmDevice {
    fn open(&self, _flags: u32) -> Result<Arc<dyn FileOps>> {
        if self.open.swap(true, Ordering::AcqRel) {
            return Err(Errno::EBUSY);
        }
        Ok(Arc::new(TpmFile {
            chip: self.chip.clone(),
            open: self.open.clone(),
            response: SpinLock::new(Response::default()),
        }))
    }
}

/// The response of the last command of an open file, and the part of it that a read gave.
/// `sending` tells that a write sends a command now.
#[derive(Default)]
struct Response {
    data: Vec<u8>,
    read: usize,
    sending: bool,
}

/// An open file of `/dev/tpm0`.
pub struct TpmFile {
    chip: Arc<Chip>,
    open: Arc<AtomicBool>,
    response: SpinLock<Response>,
}

impl Drop for TpmFile {
    fn drop(&mut self) {
        self.open.store(false, Ordering::Release);
    }
}

impl FileOps for TpmFile {
    fn read(&self, _file: &File, buf: &mut [u8]) -> Result<usize> {
        let mut r = self.response.lock();
        let n = buf.len().min(r.data.len() - r.read);
        buf[..n].copy_from_slice(&r.data[r.read..r.read + n]);
        r.read += n;
        if r.read == r.data.len() {
            r.data = Vec::new();
            r.read = 0;
        }
        Ok(n)
    }

    /// Sends the command, as `tpm_common_write` of Linux. A command must be one write.
    fn write(&self, _file: &File, buf: &[u8]) -> Result<usize> {
        {
            let mut r = self.response.lock();
            if r.sending || !r.data.is_empty() {
                return Err(Errno::EBUSY);
            }
            if buf.len() > cmd::BUFSIZE {
                return Err(Errno::E2BIG);
            }
            r.sending = true;
        }
        let result = self.chip.command(buf);
        let mut r = self.response.lock();
        r.sending = false;
        r.data = result?.1;
        r.read = 0;
        Ok(buf.len())
    }

    fn whole_write(&self) -> bool {
        true
    }

    fn poll(&self, _file: &File) -> u32 {
        if self.response.lock().data.is_empty() {
            POLLOUT | POLLWRNORM
        } else {
            POLLIN | POLLRDNORM
        }
    }

    fn pollable(&self) -> bool {
        true
    }
}

/// The text of a digest, as the files of `pcr-sha256` of Linux: hexadecimal with capital letters,
/// and a line feed.
fn hex(digest: &[u8]) -> String {
    let mut s = String::with_capacity(digest.len() * 2 + 1);
    for b in digest {
        let _ = write!(s, "{b:02X}");
    }
    s.push('\n');
    s
}

/// The files of the directory `rest` below the directory of a TPM device in sysfs, as the
/// attribute groups of tpm-sysfs.c of Linux.
pub fn sysfs(chip: &Chip, rest: &[&str]) -> Option<Vec<(String, SysEntry)>> {
    match rest {
        [] => Some(alloc::vec![
            (String::from("pcr-sha256"), SysEntry::Dir),
            (String::from("tpm_version_major"), SysEntry::File(b"2\n".to_vec())),
        ]),
        ["pcr-sha256"] => {
            let digests = chip.pcr_read_bank(cmd::ALG_SHA256).ok()?;
            let files = digests.iter().enumerate();
            Some(
                files.map(|(i, d)| (format!("{i}"), SysEntry::File(hex(d).into_bytes()))).collect(),
            )
        }
        _ => None,
    }
}

/// The attributes of the class `tpm` for `rk_vfs::device::set_class_attrs`. The device
/// `/dev/tpm0` is the chip of `crate::chip`.
fn class_attrs(d: &DeviceInfo, rest: &[&str]) -> Option<Vec<(String, SysEntry)>> {
    if d.rdev != TPM0_RDEV {
        return None;
    }
    let chip = crate::chip()?;
    sysfs(&chip, rest)
}

/// Adds `/dev/tpm0` for `chip` to the devices, and its attributes to sysfs.
pub fn register(chip: Arc<Chip>) {
    use rk_vfs::device;

    device::register_char(TPM0_RDEV, Arc::new(TpmDevice::new(chip)));
    device::register_major(false, MISC_MAJOR, "misc");
    device::set_class_attrs(CLASS, class_attrs);
    device::add_device(DeviceInfo {
        name: String::from("tpm0"),
        class: CLASS,
        rdev: TPM0_RDEV,
        block: false,
        perm: 0o600,
    });
}
