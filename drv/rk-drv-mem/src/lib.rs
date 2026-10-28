//! The memory devices of rukernel and the kernel random generator.
//!
//! The devices have the major number 1, as drivers/char/mem.c in Linux: `/dev/null`, `/dev/zero`,
//! `/dev/full`, `/dev/random` and `/dev/urandom`. The two random devices and `getrandom` read the
//! same ChaCha20 generator. The CPU gives its seed at boot. A write to a random device is
//! accepted and does not change the generator, as a write without `RNDADDENTROPY` in Linux. The
//! generator is ready from the boot, so the entropy count is always full.
//! `/dev/kmsg` has the minor number 11, as in Linux.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod kmsg;

use alloc::sync::Arc;
use rk_abi::Errno;
use rk_frame::sync::SpinLock;
use rk_lib::chacha::ChaChaRng;
use rk_vfs::device::{self, CharDevice, makedev};
use rk_vfs::file::UserMemory;
use rk_vfs::inode::Result;
use rk_vfs::{File, FileOps};

/// The major number of the memory devices.
pub const MEM_MAJOR: u32 = 1;

/// A memory device and its minor number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemDevice {
    /// `/dev/null`: a read gives the end of the file, and a write takes all the bytes.
    Null = 3,
    /// `/dev/zero`: a read gives zeros, and a write takes all the bytes.
    Zero = 5,
    /// `/dev/full`: a read gives zeros, and a write gives `ENOSPC`.
    Full = 7,
    /// `/dev/random`.
    Random = 8,
    /// `/dev/urandom`.
    Urandom = 9,
}

impl MemDevice {
    /// Each memory device.
    pub const ALL: [Self; 5] = [Self::Null, Self::Zero, Self::Full, Self::Random, Self::Urandom];

    /// The name of the device file in `/dev`.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Null => "null",
            Self::Zero => "zero",
            Self::Full => "full",
            Self::Random => "random",
            Self::Urandom => "urandom",
        }
    }

    /// The device number.
    pub const fn rdev(self) -> u64 {
        makedev(MEM_MAJOR, self as u32)
    }
}

static RNG: SpinLock<Option<ChaChaRng>> = SpinLock::new(None);

/// Fills `buf` with random bytes from the kernel generator, as `get_random_bytes` in Linux. The
/// first call takes a seed from the CPU.
pub fn get_random_bytes(buf: &mut [u8]) {
    let mut rng = RNG.lock();
    let rng = rng.get_or_insert_with(|| {
        let mut seed = [0u8; 32];
        for chunk in seed.chunks_mut(8) {
            chunk.copy_from_slice(&rk_frame::arch::random_seed().to_le_bytes());
        }
        ChaChaRng::new(seed)
    });
    rng.fill(buf);
}

/// Mixes `value` into the kernel generator, for example the time of an interrupt.
pub fn add_randomness(value: u64) {
    if let Some(rng) = RNG.lock().as_mut() {
        rng.mix(value);
    }
}

impl FileOps for MemDevice {
    fn read(&self, _file: &File, buf: &mut [u8]) -> Result<usize> {
        match self {
            Self::Null => Ok(0),
            Self::Zero | Self::Full => {
                buf.fill(0);
                Ok(buf.len())
            }
            Self::Random | Self::Urandom => {
                get_random_bytes(buf);
                Ok(buf.len())
            }
        }
    }

    fn write(&self, _file: &File, buf: &[u8]) -> Result<usize> {
        match self {
            Self::Full => Err(Errno::ENOSPC),
            _ => Ok(buf.len()),
        }
    }

    fn read_at(&self, file: &File, _offset: u64, buf: &mut [u8]) -> Result<usize> {
        self.read(file, buf)
    }

    fn write_at(&self, file: &File, _offset: u64, buf: &[u8]) -> Result<usize> {
        self.write(file, buf)
    }

    fn seekable(&self) -> bool {
        // An `lseek` on a memory device succeeds and has no effect, as in Linux.
        true
    }

    fn poll(&self, _file: &File) -> u32 {
        rk_abi::native::poll::POLLIN | rk_abi::native::poll::POLLOUT
    }

    fn ioctl(&self, _file: &File, cmd: u32, arg: usize, mem: &dyn UserMemory) -> Result<usize> {
        if !matches!(self, Self::Random | Self::Urandom) {
            return Err(Errno::ENOTTY);
        }
        random_ioctl(cmd, arg, mem)
    }
}

/// The entropy count of the input pool in bits. The generator is ready at boot, so the count is
/// always full, as `input_pool.init_bits` of Linux after the initialization.
pub const ENTROPY_BITS: u32 = 256;

/// The `ioctl` commands of the random devices, from `<linux/random.h>`.
mod rnd {
    /// Gives the entropy count, as an `int`.
    pub(crate) const RNDGETENTCNT: u32 = 0x8004_5200;
    /// Adds to the entropy count.
    pub(crate) const RNDADDTOENTCNT: u32 = 0x4004_5201;
    /// Adds bytes to the pool, from a `struct rand_pool_info`.
    pub(crate) const RNDADDENTROPY: u32 = 0x4008_5203;
    /// Sets the entropy count to 0.
    pub(crate) const RNDZAPENTCNT: u32 = 0x5204;
    /// Clears the pool. Linux takes it as `RNDZAPENTCNT`.
    pub(crate) const RNDCLEARPOOL: u32 = 0x5206;
    /// Seeds the generator again.
    pub(crate) const RNDRESEEDCRNG: u32 = 0x5207;
}

/// The `ioctl` of `/dev/random` and `/dev/urandom`, as `random_ioctl` in drivers/char/random.c of
/// Linux. The count stays full, so the commands that change it only check the capability.
fn random_ioctl(cmd: u32, arg: usize, mem: &dyn UserMemory) -> Result<usize> {
    let admin = || rk_vfs::cred::current().capable(rk_vfs::cred::cap::SYS_ADMIN);
    match cmd {
        rnd::RNDGETENTCNT => {
            mem.write(arg, &ENTROPY_BITS.to_ne_bytes())?;
            Ok(0)
        }
        rnd::RNDADDTOENTCNT | rnd::RNDZAPENTCNT | rnd::RNDCLEARPOOL | rnd::RNDRESEEDCRNG => {
            if !admin() {
                return Err(Errno::EPERM);
            }
            Ok(0)
        }
        rnd::RNDADDENTROPY => {
            if !admin() {
                return Err(Errno::EPERM);
            }
            // `struct rand_pool_info`: the entropy count, the size of the buffer and the buffer.
            let mut head = [0u8; 8];
            mem.read(arg, &mut head)?;
            let count = i32::from_ne_bytes([head[0], head[1], head[2], head[3]]);
            let size = i32::from_ne_bytes([head[4], head[5], head[6], head[7]]);
            if count < 0 || size < 0 {
                return Err(Errno::EINVAL);
            }
            let mut buf = alloc::vec![0u8; (size as usize).min(1 << 20)];
            mem.read(arg + 8, &mut buf)?;
            for chunk in buf.chunks(8) {
                let mut word = [0u8; 8];
                word[..chunk.len()].copy_from_slice(chunk);
                add_randomness(u64::from_ne_bytes(word));
            }
            Ok(0)
        }
        _ => Err(Errno::EINVAL),
    }
}

impl CharDevice for MemDevice {
    fn open(&self, _flags: u32) -> Result<Arc<dyn FileOps>> {
        Ok(Arc::new(*self))
    }
}

/// Adds the memory devices and `/dev/kmsg` to the table of character devices.
pub fn init() {
    for dev in MemDevice::ALL {
        device::register_char(dev.rdev(), Arc::new(dev));
    }
    kmsg::init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_numbers() {
        assert_eq!(MemDevice::Null.rdev(), makedev(1, 3));
        assert_eq!(MemDevice::Urandom.rdev(), makedev(1, 9));
        assert_eq!(
            MemDevice::ALL.map(MemDevice::name),
            ["null", "zero", "full", "random", "urandom"]
        );
    }
}
