//! `/dev/uinput`, as drivers/input/misc/uinput.c of Linux. A process makes an input device: it
//! sets the bits of the device with the `UI_SET_*BIT` commands, gives the name and the identity
//! with a write of `struct uinput_user_dev` or with `UI_DEV_SETUP`, and adds the device with
//! `UI_DEV_CREATE`. `UI_DEV_DESTROY` or the last close removes the device.
//!
//! A write of events to a device is accepted, but the handlers do not get the events yet.

use crate::device::{self, CharDevice, DeviceInfo, makedev};
use crate::file::FileOps;
use crate::inode::Result;
use crate::input::{self, Bits, InputId, Setup};
use crate::loopdev::MISC_MAJOR;
use crate::{File, UserMemory};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_frame::sync::SpinLock;

/// The minor number of `/dev/uinput`, `UINPUT_MINOR` of Linux.
pub const UINPUT_MINOR: u32 = 223;

/// The version of the interface that `UI_GET_VERSION` gives, `UINPUT_VERSION` of Linux.
const VERSION: u32 = 5;

/// The length of the name in the structures of uinput, `UINPUT_MAX_NAME_SIZE` of Linux.
const NAME_SIZE: usize = 80;

/// The size of `struct uinput_user_dev`: the name, `struct input_id`, `ff_effects_max` and four
/// arrays of 64 `int` for the absolute axes.
const USER_DEV_SIZE: usize = NAME_SIZE + 8 + 4 + 4 * 64 * 4;

/// The size of `struct uinput_setup`: `struct input_id`, the name and `ff_effects_max`.
const SETUP_SIZE: usize = 8 + NAME_SIZE + 4;

/// The size of `struct input_event` on a 64-bit machine.
const EVENT_SIZE: usize = 24;

/// The commands of `<linux/uinput.h>`, as `_IO`, `_IOW` and `_IOR` of Linux give them.
mod cmd {
    const fn ioc(dir: u32, nr: u32, size: u32) -> u32 {
        (dir << 30) | (size << 16) | ((b'U' as u32) << 8) | nr
    }
    const W: u32 = 1;
    const R: u32 = 2;
    pub(super) const UI_DEV_CREATE: u32 = ioc(0, 1, 0);
    pub(super) const UI_DEV_DESTROY: u32 = ioc(0, 2, 0);
    pub(super) const UI_DEV_SETUP: u32 = ioc(W, 3, super::SETUP_SIZE as u32);
    pub(super) const UI_ABS_SETUP: u32 = ioc(W, 4, 28);
    pub(super) const UI_GET_VERSION: u32 = ioc(R, 45, 4);
    pub(super) const UI_SET_EVBIT: u32 = ioc(W, 100, 4);
    pub(super) const UI_SET_KEYBIT: u32 = ioc(W, 101, 4);
    pub(super) const UI_SET_RELBIT: u32 = ioc(W, 102, 4);
    pub(super) const UI_SET_ABSBIT: u32 = ioc(W, 103, 4);
    pub(super) const UI_SET_MSCBIT: u32 = ioc(W, 104, 4);
    pub(super) const UI_SET_LEDBIT: u32 = ioc(W, 105, 4);
    pub(super) const UI_SET_SNDBIT: u32 = ioc(W, 106, 4);
    pub(super) const UI_SET_FFBIT: u32 = ioc(W, 107, 4);
    pub(super) const UI_SET_PHYS: u32 = ioc(W, 108, 8);
    pub(super) const UI_SET_SWBIT: u32 = ioc(W, 109, 4);
    pub(super) const UI_SET_PROPBIT: u32 = ioc(W, 110, 4);
    /// `UI_GET_SYSNAME(len)` without the length.
    pub(super) const UI_GET_SYSNAME: u32 = ioc(R, 44, 0);
    /// The bits of a command without the size.
    pub(super) const NO_SIZE: u32 = 0xc000_ffff;
}

/// The state of an open file of `/dev/uinput`, as `enum uinput_state` of Linux.
#[derive(Default)]
struct State {
    /// The facts about the device. The name is not empty after the setup.
    setup: Setup,
    /// The number of the input device after `UI_DEV_CREATE`.
    created: Option<u32>,
    /// `UI_DEV_CREATE` adds the device now. The lock is not held while the device sends its
    /// events.
    creating: bool,
}

/// An open file of `/dev/uinput`.
struct Uinput {
    state: SpinLock<State>,
}

/// The name in the bytes `b`, up to the first 0.
fn name(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

/// `struct input_id` in the bytes `b`.
fn input_id(b: &[u8]) -> InputId {
    let u16_at = |i: usize| u16::from_le_bytes([b[i], b[i + 1]]);
    InputId { bustype: u16_at(0), vendor: u16_at(2), product: u16_at(4), version: u16_at(6) }
}

impl State {
    /// Sets the name and the identity, as `uinput_dev_setup` of Linux. An empty name gives
    /// `EINVAL`.
    fn set(&mut self, name: String, id: InputId) -> Result<()> {
        if self.busy() || name.is_empty() {
            return Err(Errno::EINVAL);
        }
        self.setup.name = name;
        self.setup.id = id;
        Ok(())
    }

    /// Sets the bit `bit` of the bitmap `kind`. A device that exists does not change.
    fn set_bit(&mut self, kind: Bits, bit: usize) -> Result<()> {
        if self.busy() {
            return Err(Errno::EINVAL);
        }
        self.setup.caps.set(kind, bit)
    }

    /// Tells if the device exists or comes now. Its facts do not change then.
    fn busy(&self) -> bool {
        self.created.is_some() || self.creating
    }
}

impl Uinput {
    /// Adds the device, as `uinput_create_device` of Linux. The device must have a name.
    fn create(&self) -> Result<()> {
        let setup = {
            let mut s = self.state.lock();
            if s.busy() || s.setup.name.is_empty() {
                return Err(Errno::EINVAL);
            }
            s.creating = true;
            s.setup.clone()
        };
        let number = input::register(setup);
        let mut s = self.state.lock();
        s.created = Some(number);
        s.creating = false;
        Ok(())
    }

    /// Removes the device, if there is one.
    fn destroy(&self) {
        let number = self.state.lock().created.take();
        if let Some(number) = number {
            input::unregister(number);
        }
    }
}

impl FileOps for Uinput {
    fn read(&self, _file: &File, _buf: &mut [u8]) -> Result<usize> {
        // The device sends no force feedback requests.
        if self.state.lock().created.is_none() { Err(Errno::ENODEV) } else { Err(Errno::EAGAIN) }
    }

    fn write(&self, _file: &File, buf: &[u8]) -> Result<usize> {
        let mut s = self.state.lock();
        if s.busy() {
            // The events of the device. The handlers do not get them yet.
            return if buf.len().is_multiple_of(EVENT_SIZE) {
                Ok(buf.len())
            } else {
                Err(Errno::EINVAL)
            };
        }
        // `struct uinput_user_dev`, as `uinput_setup_device_legacy` of Linux.
        if buf.len() != USER_DEV_SIZE {
            return Err(Errno::EINVAL);
        }
        s.set(name(&buf[..NAME_SIZE]), input_id(&buf[NAME_SIZE..NAME_SIZE + 8]))?;
        Ok(buf.len())
    }

    fn ioctl(&self, _file: &File, cmd: u32, arg: usize, mem: &dyn UserMemory) -> Result<usize> {
        let mut s = self.state.lock();
        let bit = |kind| (kind, arg);
        let set = match cmd {
            cmd::UI_SET_EVBIT => Some(bit(Bits::Ev)),
            cmd::UI_SET_KEYBIT => Some(bit(Bits::Key)),
            cmd::UI_SET_RELBIT => Some(bit(Bits::Rel)),
            cmd::UI_SET_ABSBIT => Some(bit(Bits::Abs)),
            cmd::UI_SET_MSCBIT => Some(bit(Bits::Msc)),
            cmd::UI_SET_LEDBIT => Some(bit(Bits::Led)),
            cmd::UI_SET_SNDBIT => Some(bit(Bits::Snd)),
            cmd::UI_SET_FFBIT => Some(bit(Bits::Ff)),
            cmd::UI_SET_SWBIT => Some(bit(Bits::Sw)),
            cmd::UI_SET_PROPBIT => Some(bit(Bits::Prop)),
            _ => None,
        };
        if let Some((kind, bit)) = set {
            return s.set_bit(kind, bit).map(|()| 0);
        }
        match cmd {
            cmd::UI_GET_VERSION => mem.write(arg, &VERSION.to_ne_bytes()).map(|()| 0),
            cmd::UI_DEV_SETUP => {
                let mut b = [0u8; SETUP_SIZE];
                mem.read(arg, &mut b)?;
                s.set(name(&b[8..8 + NAME_SIZE]), input_id(&b[..8])).map(|()| 0)
            }
            // The ranges of the absolute axes are not kept yet.
            cmd::UI_ABS_SETUP => {
                if s.busy() {
                    Err(Errno::EINVAL)
                } else {
                    Ok(0)
                }
            }
            cmd::UI_SET_PHYS => {
                if s.busy() {
                    return Err(Errno::EINVAL);
                }
                // The argument is the address of a string of at most 1024 bytes.
                let mut phys = Vec::new();
                let mut c = [0u8];
                while phys.len() < 1024 {
                    mem.read(arg + phys.len(), &mut c)?;
                    if c[0] == 0 {
                        break;
                    }
                    phys.push(c[0]);
                }
                s.setup.phys = String::from_utf8_lossy(&phys).into_owned();
                Ok(0)
            }
            cmd::UI_DEV_CREATE => {
                drop(s);
                self.create().map(|()| 0)
            }
            cmd::UI_DEV_DESTROY => {
                drop(s);
                self.destroy();
                Ok(0)
            }
            c if c & cmd::NO_SIZE == cmd::UI_GET_SYSNAME => {
                // The name of the device in sysfs and a 0, cut to the length of the buffer.
                let number = s.created.ok_or(Errno::ENOENT)?;
                let mut text = alloc::format!("input{number}").into_bytes();
                text.push(0);
                let len = text.len().min(((c >> 16) & 0x3fff) as usize);
                mem.write(arg, &text[..len])?;
                Ok(len)
            }
            _ => Err(Errno::EINVAL),
        }
    }
}

impl Drop for Uinput {
    fn drop(&mut self) {
        self.destroy();
    }
}

/// The driver of `/dev/uinput`.
struct Driver;

impl CharDevice for Driver {
    fn open(&self, _flags: u32) -> Result<Arc<dyn FileOps>> {
        Ok(Arc::new(Uinput { state: SpinLock::new(State::default()) }))
    }
}

/// Adds the input handlers and `/dev/uinput`. The kernel calls this one time at boot.
pub fn init() {
    input::init();
    let rdev = makedev(MISC_MAJOR, UINPUT_MINOR);
    device::register_char(rdev, Arc::new(Driver));
    device::add_device(DeviceInfo {
        name: String::from("uinput"),
        class: "misc",
        rdev,
        block: false,
        perm: 0o600,
    });
}
