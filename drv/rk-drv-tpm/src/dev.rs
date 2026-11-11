//! `/dev/tpm0`, `/dev/tpmrm0` and `/sys/class/tpm/tpm0`, as tpm-dev.c, tpmrm-dev.c,
//! tpm-dev-common.c and tpm-sysfs.c of Linux.
//!
//! One file of `/dev/tpm0` can be open at a time. A second open gives `EBUSY`. Many files of
//! `/dev/tpmrm0` can be open, and each one has a space of the resource manager of `space`. A
//! write sends one command to the TPM and keeps the response. A read gives the response, and a
//! part of it if the buffer is small. A second write before a read gives `EBUSY`. A write after a
//! read of a part of the response drops the rest, as Linux. `poll` tells that a read can come
//! when the file has a response, and that a write can come when it does not.
//!
//! The directory of the device in sysfs has `tpm_version_major`, and `pcr-sha256` with a file for
//! each PCR of the SHA-256 bank. Each file has the digest in hexadecimal, as Linux shows it.

use crate::space::{self, Space};
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

/// The major number of `/dev/tpmrm0`. Linux takes a free major number for the class `tpm`, and
/// it is often 253.
pub const TPM_MAJOR: u32 = 253;
/// The minor number of `/dev/tpmrm0`: `TPM_NUM_DEVICES` of Linux.
pub const TPMRM_MINOR: u32 = 65536;
/// The device number of `/dev/tpmrm0`.
pub const TPMRM0_RDEV: u64 = makedev(TPM_MAJOR, TPMRM_MINOR);

/// The class of the TPM devices with a resource manager in sysfs.
pub const RM_CLASS: &str = "tpmrm";

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
        Ok(Arc::new(TpmFile::new(self.chip.clone(), Some(self.open.clone()), None)))
    }
}

/// The driver of `/dev/tpmrm0`, as tpmrm-dev.c of Linux. Each open file has its own space of
/// the resource manager, and many files can be open.
pub struct TpmrmDevice {
    chip: Arc<Chip>,
}

impl TpmrmDevice {
    /// Makes the driver of the device of `chip`.
    pub fn new(chip: Arc<Chip>) -> Self {
        Self { chip }
    }
}

impl CharDevice for TpmrmDevice {
    fn open(&self, _flags: u32) -> Result<Arc<dyn FileOps>> {
        Ok(Arc::new(TpmFile::new(self.chip.clone(), None, Some(Space::new()))))
    }
}

/// The response of the last command of an open file, as the fields of `struct file_priv` of
/// Linux.
struct Response {
    /// The response, and the part of it that a read gave.
    data: Vec<u8>,
    read: usize,
    /// The error of a command that a nonblocking write sent. The next read gives it.
    error: Option<Errno>,
    /// Tells that a read came after the last write, as `response_read` of Linux. A new write
    /// can then come before the read of all of the response.
    response_read: bool,
    /// Tells that a write sends a command now.
    sending: bool,
}

impl Response {
    /// Tells if a read has something to give, as a `response_length` that is not 0 in Linux.
    fn pending(&self) -> bool {
        self.error.is_some() || self.read < self.data.len()
    }
}

/// An open file of `/dev/tpm0` or `/dev/tpmrm0`.
pub struct TpmFile {
    chip: Arc<Chip>,
    /// The flag of `/dev/tpm0` that tells that it is open.
    open: Option<Arc<AtomicBool>>,
    /// The space of a file of `/dev/tpmrm0`. A write takes it while it sends the command.
    space: Option<SpinLock<Space>>,
    response: SpinLock<Response>,
}

impl TpmFile {
    fn new(chip: Arc<Chip>, open: Option<Arc<AtomicBool>>, space: Option<Space>) -> Self {
        let response = Response {
            data: Vec::new(),
            read: 0,
            error: None,
            response_read: true,
            sending: false,
        };
        Self { chip, open, space: space.map(SpinLock::new), response: SpinLock::new(response) }
    }

    /// Sends the command `c`, in the space of the file if it has one.
    fn send(&self, c: &[u8]) -> Result<Vec<u8>> {
        let Some(space) = &self.space else {
            return self.chip.command(c).map(|r| r.1);
        };
        // Only one write of the file sends at a time, so the space can go out of its lock while
        // the command waits for the TPM.
        let mut s = core::mem::take(&mut *space.lock());
        let result = space::transmit(&mut self.chip.lock(), &mut s, c);
        *space.lock() = s;
        result
    }
}

impl Drop for TpmFile {
    fn drop(&mut self) {
        if let Some(space) = &self.space {
            let mut s = core::mem::take(&mut *space.lock());
            if !s.is_empty() {
                space::release(&mut self.chip.lock(), &mut s);
            }
        }
        if let Some(open) = &self.open {
            open.store(false, Ordering::Release);
        }
    }
}

impl FileOps for TpmFile {
    /// Gives the response, or the next part of it, as `tpm_common_read` of Linux. After a
    /// nonblocking write, it gives the error of the command.
    fn read(&self, _file: &File, buf: &mut [u8]) -> Result<usize> {
        let mut r = self.response.lock();
        if !r.pending() {
            return Ok(0);
        }
        r.response_read = true;
        if let Some(e) = r.error.take() {
            return Err(e);
        }
        let n = buf.len().min(r.data.len() - r.read);
        buf[..n].copy_from_slice(&r.data[r.read..r.read + n]);
        r.read += n;
        if r.read == r.data.len() {
            r.data = Vec::new();
            r.read = 0;
        }
        Ok(n)
    }

    /// Sends the command, as `tpm_common_write` of Linux. A command must be one write. A write
    /// before the read of the last response gives `EBUSY`, but after a read of a part of it, the
    /// write drops the rest. A nonblocking write keeps the error of the command for the next
    /// read.
    fn write(&self, file: &File, buf: &[u8]) -> Result<usize> {
        if buf.len() > cmd::BUFSIZE {
            return Err(Errno::E2BIG);
        }
        {
            let mut r = self.response.lock();
            if (!r.response_read && r.pending()) || r.sending {
                return Err(Errno::EBUSY);
            }
            let size = cmd::size(buf).filter(|&n| buf.len() >= 6 && buf.len() >= n);
            if size.is_none() {
                return Err(Errno::EINVAL);
            }
            r.data = Vec::new();
            r.read = 0;
            r.error = None;
            r.response_read = false;
            r.sending = true;
        }
        // Linux sends the bytes that the size field gives.
        let size = cmd::size(buf).unwrap_or(buf.len());
        let result = self.send(&buf[..size]);
        let mut r = self.response.lock();
        r.sending = false;
        match result {
            Ok(data) => r.data = data,
            Err(e) if file.nonblock() => r.error = Some(e),
            Err(e) => return Err(e),
        }
        Ok(buf.len())
    }

    fn whole_write(&self) -> bool {
        true
    }

    fn poll(&self, _file: &File) -> u32 {
        if self.response.lock().pending() { POLLIN | POLLRDNORM } else { POLLOUT | POLLWRNORM }
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

/// Adds `/dev/tpm0` for `chip` to the devices, and its attributes to sysfs. If the chip has the
/// attributes of its commands, it adds `/dev/tpmrm0` too.
pub fn register(chip: Arc<Chip>) {
    use rk_vfs::device;

    device::register_char(TPM0_RDEV, Arc::new(TpmDevice::new(chip.clone())));
    device::register_major(false, MISC_MAJOR, "misc");
    device::set_class_attrs(CLASS, class_attrs);
    device::add_device(DeviceInfo {
        name: String::from("tpm0"),
        class: CLASS,
        rdev: TPM0_RDEV,
        block: false,
        perm: 0o600,
    });
    // The resource manager needs the attributes of the commands, as Linux.
    if chip.has_cc_attrs() {
        device::register_char(TPMRM0_RDEV, Arc::new(TpmrmDevice::new(chip)));
        device::register_major(false, TPM_MAJOR, "tpm");
        device::add_device(DeviceInfo {
            name: String::from("tpmrm0"),
            class: RM_CLASS,
            rdev: TPMRM0_RDEV,
            block: false,
            perm: 0o600,
        });
    }
}
