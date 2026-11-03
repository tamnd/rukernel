//! The input devices, as drivers/input/input.c of Linux, with the handlers of mousedev.c and
//! evdev.c.
//!
//! An input device has the number `N`, and its path in sysfs is `/devices/virtual/input/inputN`.
//! When a driver adds a device, the device gets its handlers, as the handlers of Linux that are in
//! the kernel: `mouseM` (major 13, minor 32 + M) for a mouse or a touchpad, and then `eventE`
//! (major 13, minor 64 + E) for each device. Each handler is a character device in
//! `/dev/input` and a directory in the directory of its input device. The events of a device are
//! `add` of the device and then `add` of each handler, and at the end `remove` of each handler
//! and then `remove` of the device, as Linux sends them.
//!
//! The handler files open, but they give no input events yet: a read gives `EAGAIN`.

use crate::device::{self, CharDevice, DeviceInfo, makedev};
use crate::file::FileOps;
use crate::inode::Result;
use crate::uevent::{self, Action, Event};
use crate::{File, UserMemory};
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Write;
use rk_abi::Errno;
use rk_frame::sync::SpinLock;

/// The major number of the input handlers, `INPUT_MAJOR` of Linux.
pub const INPUT_MAJOR: u32 = 13;

/// The first minor number of the mouse handlers, `MOUSEDEV_MINOR_BASE` of Linux.
const MOUSE_MINOR_BASE: u32 = 32;

/// The first minor number of the event handlers, `EVDEV_MINOR_BASE` of Linux.
const EVENT_MINOR_BASE: u32 = 64;

/// The number of handlers of one kind, `MOUSEDEV_MINORS` and `EVDEV_MINORS` of Linux.
const HANDLER_MINORS: u32 = 32;

/// The types of events (`EV_*`) and the input properties (`INPUT_PROP_*`), each with a bitmap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bits {
    /// The types of events, `evbit`.
    Ev,
    /// The keys and buttons, `keybit`.
    Key,
    /// The relative axes, `relbit`.
    Rel,
    /// The absolute axes, `absbit`.
    Abs,
    /// The other events, `mscbit`.
    Msc,
    /// The LEDs, `ledbit`.
    Led,
    /// The sounds, `sndbit`.
    Snd,
    /// The force feedback effects, `ffbit`.
    Ff,
    /// The switches, `swbit`.
    Sw,
    /// The properties, `propbit`.
    Prop,
}

/// The bits of `evbit`, as include/uapi/linux/input-event-codes.h of Linux.
pub mod ev {
    /// `EV_SYN`.
    pub const SYN: usize = 0;
    /// `EV_KEY`.
    pub const KEY: usize = 1;
    /// `EV_REL`.
    pub const REL: usize = 2;
    /// `EV_ABS`.
    pub const ABS: usize = 3;
}

/// `BTN_LEFT`.
pub const BTN_LEFT: usize = 0x110;
/// `BTN_TOUCH`.
pub const BTN_TOUCH: usize = 0x14a;
/// `REL_X` and `ABS_X`.
pub const AXIS_X: usize = 0;
/// `REL_Y` and `ABS_Y`.
pub const AXIS_Y: usize = 1;

/// The number of 64-bit words in the largest bitmap, the one of the keys.
const WORDS: usize = 12;

impl Bits {
    /// Each bitmap, in the order of the variables of an event.
    const ALL: [Self; 10] = [
        Self::Prop,
        Self::Ev,
        Self::Key,
        Self::Rel,
        Self::Abs,
        Self::Msc,
        Self::Led,
        Self::Snd,
        Self::Ff,
        Self::Sw,
    ];

    /// The largest bit, as `EV_MAX`, `KEY_MAX` and the others of Linux.
    pub const fn max(self) -> usize {
        match self {
            Self::Ev => 0x1f,
            Self::Key => 0x2ff,
            Self::Rel => 0x0f,
            Self::Abs => 0x3f,
            Self::Msc => 0x07,
            Self::Led => 0x0f,
            Self::Snd => 0x07,
            Self::Ff => 0x7f,
            Self::Sw => 0x11,
            Self::Prop => 0x1f,
        }
    }

    /// The name of the bitmap in an event and in `/proc/bus/input/devices`.
    const fn name(self) -> &'static str {
        match self {
            Self::Ev => "EV",
            Self::Key => "KEY",
            Self::Rel => "REL",
            Self::Abs => "ABS",
            Self::Msc => "MSC",
            Self::Led => "LED",
            Self::Snd => "SND",
            Self::Ff => "FF",
            Self::Sw => "SW",
            Self::Prop => "PROP",
        }
    }

    /// The type of event of the bitmap. The device has the bitmap only with this bit in
    /// `evbit`. The types and the properties are always there.
    const fn ev(self) -> Option<usize> {
        match self {
            Self::Ev | Self::Prop => None,
            Self::Key => Some(1),
            Self::Rel => Some(2),
            Self::Abs => Some(3),
            Self::Msc => Some(4),
            Self::Sw => Some(5),
            Self::Led => Some(0x11),
            Self::Snd => Some(0x12),
            Self::Ff => Some(0x15),
        }
    }

    /// The file of the bitmap in the directory `capabilities` in sysfs.
    const fn file(self) -> &'static str {
        match self {
            Self::Ev => "ev",
            Self::Key => "key",
            Self::Rel => "rel",
            Self::Abs => "abs",
            Self::Msc => "msc",
            Self::Led => "led",
            Self::Snd => "snd",
            Self::Ff => "ff",
            Self::Sw => "sw",
            Self::Prop => "properties",
        }
    }

    /// The letter of the bitmap in `MODALIAS`, as `input_print_modalias` of Linux.
    const fn letter(self) -> Option<char> {
        match self {
            Self::Ev => Some('e'),
            Self::Key => Some('k'),
            Self::Rel => Some('r'),
            Self::Abs => Some('a'),
            Self::Msc => Some('m'),
            Self::Led => Some('l'),
            Self::Snd => Some('s'),
            Self::Ff => Some('f'),
            Self::Sw => Some('w'),
            Self::Prop => None,
        }
    }

    /// The number of 64-bit words of the bitmap, `BITS_TO_LONGS(max + 1)`.
    const fn words(self) -> usize {
        self.max() / 64 + 1
    }
}

/// The bitmaps of a device.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Caps {
    words: [[u64; WORDS]; 10],
}

impl Caps {
    fn index(kind: Bits) -> usize {
        kind as usize
    }

    /// Sets the bit `bit` of the bitmap `kind`. Gives `EINVAL` for a bit after the largest bit.
    pub fn set(&mut self, kind: Bits, bit: usize) -> Result<()> {
        if bit > kind.max() {
            return Err(Errno::EINVAL);
        }
        self.words[Self::index(kind)][bit / 64] |= 1 << (bit % 64);
        Ok(())
    }

    /// Tells if the bitmap `kind` has the bit `bit`.
    pub fn has(&self, kind: Bits, bit: usize) -> bool {
        bit <= kind.max() && self.words[Self::index(kind)][bit / 64] & (1 << (bit % 64)) != 0
    }

    /// The bitmap `kind` as text, as `input_print_bitmap` of Linux: the words in hexadecimal from
    /// the last word that is not 0 to the first word, with a space between them.
    pub fn text(&self, kind: Bits) -> String {
        let words = &self.words[Self::index(kind)][..kind.words()];
        let last = words.iter().rposition(|&w| w != 0).unwrap_or(0);
        let mut out = String::new();
        for (i, w) in words[..=last].iter().enumerate().rev() {
            let _ = write!(out, "{w:x}");
            if i > 0 {
                out.push(' ');
            }
        }
        out
    }

    /// The bitmaps that the device has: the types and the properties, and each bitmap whose type
    /// of event is in `evbit`.
    fn present(&self) -> impl Iterator<Item = Bits> + '_ {
        Bits::ALL.into_iter().filter(|b| b.ev().is_none_or(|ev| self.has(Bits::Ev, ev)))
    }

    /// Tells if `mousedev` takes the device, as `mousedev_ids` of Linux: a mouse with the left
    /// button and the relative axes X and Y, or a touchpad or tablet with a touch or left button
    /// and the absolute axes X and Y.
    fn is_mouse(&self) -> bool {
        let key = |b| self.has(Bits::Ev, ev::KEY) && self.has(Bits::Key, b);
        let rel = self.has(Bits::Ev, ev::REL)
            && self.has(Bits::Rel, AXIS_X)
            && self.has(Bits::Rel, AXIS_Y);
        let abs = self.has(Bits::Ev, ev::ABS)
            && self.has(Bits::Abs, AXIS_X)
            && self.has(Bits::Abs, AXIS_Y);
        (rel && key(BTN_LEFT)) || (abs && (key(BTN_TOUCH) || key(BTN_LEFT)))
    }
}

/// The identity of a device, `struct input_id` of Linux.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct InputId {
    /// The bus, for example `BUS_USB` (3) or `BUS_VIRTUAL` (6).
    pub bustype: u16,
    /// The vendor.
    pub vendor: u16,
    /// The product.
    pub product: u16,
    /// The version.
    pub version: u16,
}

/// The facts about a new device that its driver gives.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Setup {
    /// The name of the device.
    pub name: String,
    /// The physical path of the device. It can be empty.
    pub phys: String,
    /// The identity.
    pub id: InputId,
    /// The bitmaps.
    pub caps: Caps,
}

/// A handler of a device: its name, for example `mouse0`, and its device number.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Handler {
    name: String,
    rdev: u64,
}

/// An input device.
#[derive(Clone, Debug, PartialEq, Eq)]
struct InputDevice {
    number: u32,
    setup: Setup,
    handlers: Vec<Handler>,
}

static DEVICES: SpinLock<Vec<InputDevice>> = SpinLock::new(Vec::new());

/// The path of the input device `number` in sysfs, below `/sys`.
fn path(number: u32) -> String {
    format!("/devices/virtual/input/input{number}")
}

/// The first number from 0 that `used` does not have.
fn first_free(used: impl Iterator<Item = u32> + Clone) -> u32 {
    (0..).find(|n| !used.clone().any(|u| u == *n)).unwrap_or(0)
}

impl InputDevice {
    /// The variables of the events of the device, as `input_dev_uevent` of Linux.
    fn vars(&self) -> Vec<String> {
        let s = &self.setup;
        let id = s.id;
        let mut out = Vec::from([
            format!("PRODUCT={:x}/{:x}/{:x}/{:x}", id.bustype, id.vendor, id.product, id.version),
            format!("NAME=\"{}\"", s.name),
        ]);
        if !s.phys.is_empty() {
            out.push(format!("PHYS=\"{}\"", s.phys));
        }
        for b in s.caps.present() {
            out.push(format!("{}={}", b.name(), s.caps.text(b)));
        }
        out.push(format!("MODALIAS={}", self.modalias()));
        out
    }

    /// The text of `modalias`, as `input_print_modalias` of Linux.
    fn modalias(&self) -> String {
        let s = &self.setup;
        let id = s.id;
        let mut out = format!(
            "input:b{:04X}v{:04X}p{:04X}e{:04X}-",
            id.bustype, id.vendor, id.product, id.version
        );
        for b in Bits::ALL {
            let Some(letter) = b.letter() else { continue };
            out.push(letter);
            // Linux does not give the keys before `KEY_MIN_INTERESTING` (`KEY_MUTE`).
            let first = if b == Bits::Key { 113 } else { 0 };
            for bit in (first..=b.max()).filter(|&bit| s.caps.has(b, bit)) {
                let _ = write!(out, "{bit:X},");
            }
        }
        out
    }

    /// The event `action` of the device.
    fn event(&self, action: Action) -> Event {
        let mut e = Event::new(action, path(self.number), "input");
        e.vars = self.vars();
        e
    }

    /// The device of the handler `h` in the list of devices.
    fn handler_info(h: &Handler) -> DeviceInfo {
        DeviceInfo {
            name: format!("input/{}", h.name),
            class: "input",
            rdev: h.rdev,
            block: false,
            perm: 0o600,
        }
    }
}

/// Adds an input device with its handlers, as `input_register_device` of Linux, and gives its
/// number. The device sends its event `add`, and then each handler sends its event `add`.
pub fn register(mut setup: Setup) -> u32 {
    // Each device has the type `EV_SYN`, and no device has the key `KEY_RESERVED`.
    let _ = setup.caps.set(Bits::Ev, ev::SYN);
    setup.caps.words[Caps::index(Bits::Key)][0] &= !1;
    let dev = {
        let mut list = DEVICES.lock();
        let number = first_free(list.iter().map(|d| d.number));
        let minors = || list.iter().flat_map(|d| d.handlers.iter().map(|h| device::minor(h.rdev)));
        let mut handlers = Vec::new();
        if setup.caps.is_mouse() {
            let used = minors().filter_map(|m| m.checked_sub(MOUSE_MINOR_BASE));
            let m = first_free(used.filter(|&m| m < HANDLER_MINORS));
            if m < HANDLER_MINORS {
                let rdev = makedev(INPUT_MAJOR, MOUSE_MINOR_BASE + m);
                handlers.push(Handler { name: format!("mouse{m}"), rdev });
            }
        }
        let used = minors().filter_map(|m| m.checked_sub(EVENT_MINOR_BASE));
        let e = first_free(used.filter(|&e| e < HANDLER_MINORS));
        if e < HANDLER_MINORS {
            let rdev = makedev(INPUT_MAJOR, EVENT_MINOR_BASE + e);
            handlers.push(Handler { name: format!("event{e}"), rdev });
        }
        let dev = InputDevice { number, setup, handlers };
        list.push(dev.clone());
        dev
    };
    uevent::send(&dev.event(Action::Add));
    for h in &dev.handlers {
        device::add_device_node(InputDevice::handler_info(h));
    }
    dev.number
}

/// Removes the input device `number`, as `input_unregister_device` of Linux. Each handler sends
/// its event `remove`, and then the device sends its event `remove`.
pub fn unregister(number: u32) {
    let Some(dev) = DEVICES.lock().iter().find(|d| d.number == number).cloned() else {
        return;
    };
    for h in &dev.handlers {
        device::remove_device(false, h.rdev);
    }
    DEVICES.lock().retain(|d| d.number != number);
    uevent::send(&dev.event(Action::Remove));
}

/// Sends the event `action` of the input device `inputN` with the name `name`, for a write to its
/// file `uevent`. `vars` come before the variables of the device. Gives `ENODEV` if there is no
/// such device.
pub fn synth(name: &str, action: Action, vars: Vec<String>) -> Result<()> {
    let dev = DEVICES.lock().iter().find(|d| format!("input{}", d.number) == name).cloned();
    let mut e = dev.ok_or(Errno::ENODEV)?.event(action);
    e.vars.splice(0..0, vars);
    uevent::send(&e);
    Ok(())
}

/// The path in sysfs of the input device of the handler `d`, if `d` is a handler.
pub(crate) fn parent(d: &DeviceInfo) -> Option<String> {
    if d.block || device::major(d.rdev) != INPUT_MAJOR {
        return None;
    }
    let list = DEVICES.lock();
    let dev = list.iter().find(|dev| dev.handlers.iter().any(|h| h.rdev == d.rdev))?;
    Some(path(dev.number))
}

/// The text of `/proc/bus/input/devices`, as `input_devices_seq_show` of Linux.
pub fn proc_devices() -> String {
    let mut out = String::new();
    for d in DEVICES.lock().iter() {
        let s = &d.setup;
        let id = s.id;
        let _ = writeln!(
            out,
            "I: Bus={:04x} Vendor={:04x} Product={:04x} Version={:04x}",
            id.bustype, id.vendor, id.product, id.version
        );
        let _ = writeln!(out, "N: Name=\"{}\"", s.name);
        let _ = writeln!(out, "P: Phys={}", s.phys);
        let _ = writeln!(out, "S: Sysfs={}", path(d.number));
        out.push_str("U: Uniq=\nH: Handlers=");
        for h in &d.handlers {
            let _ = write!(out, "{} ", h.name);
        }
        out.push('\n');
        for b in s.caps.present() {
            let _ = writeln!(out, "B: {}={}", b.name(), s.caps.text(b));
        }
        out.push('\n');
    }
    out
}

/// An entry of a directory of the input devices in sysfs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SysEntry {
    /// A directory.
    Dir,
    /// A file with its text.
    File(Vec<u8>),
    /// A symbolic link with its target.
    Link(Vec<u8>),
}

fn file(name: &str, text: String) -> (String, SysEntry) {
    (String::from(name), SysEntry::File(text.into_bytes()))
}

fn link(name: &str, to: String) -> (String, SysEntry) {
    (String::from(name), SysEntry::Link(to.into_bytes()))
}

/// The entries of `/sys/class/input`: a link to each device and to each handler.
pub fn sysfs_class() -> Vec<(String, SysEntry)> {
    let mut out = Vec::new();
    for d in DEVICES.lock().iter() {
        let name = format!("input{}", d.number);
        out.push(link(&name, format!("../../devices/virtual/input/{name}")));
        for h in &d.handlers {
            out.push(link(&h.name, format!("../../devices/virtual/input/{name}/{}", h.name)));
        }
    }
    out
}

/// The entries of the directory `/sys/devices/virtual/input/PATH`, where `path` has the parts of
/// `PATH`. Gives `None` if no directory has the path.
pub fn sysfs(path: &[&str]) -> Option<Vec<(String, SysEntry)>> {
    let list = DEVICES.lock();
    let find = |name: &str| list.iter().find(|d| format!("input{}", d.number) == name);
    let out = match *path {
        [] => list.iter().map(|d| (format!("input{}", d.number), SysEntry::Dir)).collect(),
        [name] => {
            let d = find(name)?;
            let s = &d.setup;
            let mut uevent = String::new();
            for v in d.vars() {
                uevent.push_str(&v);
                uevent.push('\n');
            }
            let mut out = alloc::vec![
                (String::from("capabilities"), SysEntry::Dir),
                (String::from("id"), SysEntry::Dir),
                file("modalias", format!("{}\n", d.modalias())),
                file("name", format!("{}\n", s.name)),
                file("phys", format!("{}\n", s.phys)),
                file("properties", format!("{}\n", s.caps.text(Bits::Prop))),
                link("subsystem", String::from("../../../../class/input")),
                file("uevent", uevent),
                file("uniq", String::from("\n")),
            ];
            out.extend(d.handlers.iter().map(|h| (h.name.clone(), SysEntry::Dir)));
            out
        }
        [name, "id"] => {
            let id = find(name)?.setup.id;
            alloc::vec![
                file("bustype", format!("{:04x}\n", id.bustype)),
                file("product", format!("{:04x}\n", id.product)),
                file("vendor", format!("{:04x}\n", id.vendor)),
                file("version", format!("{:04x}\n", id.version)),
            ]
        }
        [name, "capabilities"] => {
            let caps = &find(name)?.setup.caps;
            Bits::ALL
                .into_iter()
                .filter(|&b| b != Bits::Prop)
                .map(|b| file(b.file(), format!("{}\n", caps.text(b))))
                .collect()
        }
        [name, handler] => {
            let h = find(name)?.handlers.iter().find(|h| h.name == handler)?;
            let (major, minor) = (device::major(h.rdev), device::minor(h.rdev));
            let uevent = format!("MAJOR={major}\nMINOR={minor}\nDEVNAME=input/{}\n", h.name);
            alloc::vec![
                file("dev", format!("{major}:{minor}\n")),
                link("device", format!("../../{name}")),
                link("subsystem", String::from("../../../../../class/input")),
                file("uevent", uevent),
            ]
        }
        _ => return None,
    };
    Some(out)
}

/// An open file of a handler. It gives no input events yet.
struct HandlerFile;

impl FileOps for HandlerFile {
    fn read(&self, _file: &File, _buf: &mut [u8]) -> Result<usize> {
        Err(Errno::EAGAIN)
    }

    fn ioctl(&self, _file: &File, _cmd: u32, _arg: usize, _mem: &dyn UserMemory) -> Result<usize> {
        Err(Errno::EINVAL)
    }
}

/// The driver of the handlers, for each minor number of the major 13.
struct Handlers;

impl CharDevice for Handlers {
    fn open(&self, _flags: u32) -> Result<Arc<dyn FileOps>> {
        Ok(Arc::new(HandlerFile))
    }
}

/// Adds the driver of the handlers and the name of the major number 13. The kernel calls this
/// one time at boot.
pub fn init() {
    device::register_major(false, INPUT_MAJOR, "input");
    device::register_char_major(INPUT_MAJOR, Arc::new(Handlers));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mouse() -> Setup {
        let mut caps = Caps::default();
        for (kind, bit) in [
            (Bits::Ev, ev::KEY),
            (Bits::Key, BTN_LEFT),
            (Bits::Ev, ev::REL),
            (Bits::Rel, AXIS_X),
            (Bits::Rel, AXIS_Y),
        ] {
            caps.set(kind, bit).unwrap();
        }
        let id = InputId { bustype: 3, vendor: 1, product: 1, version: 1 };
        Setup { name: String::from("virtual-device-ltp"), phys: String::new(), id, caps }
    }

    #[test]
    fn a_bitmap_has_its_words_from_the_last_word_that_is_not_0() {
        let mut caps = Caps::default();
        assert_eq!(caps.text(Bits::Key), "0");
        caps.set(Bits::Key, BTN_LEFT).unwrap();
        assert_eq!(caps.text(Bits::Key), "10000 0 0 0 0");
        assert_eq!(caps.set(Bits::Rel, 0x10), Err(Errno::EINVAL));
    }

    #[test]
    fn a_mouse_gets_a_mouse_and_an_event_handler_with_the_variables_of_linux() {
        let number = register(mouse());
        let dev = DEVICES.lock().iter().find(|d| d.number == number).cloned().unwrap();
        let names: Vec<&str> = dev.handlers.iter().map(|h| h.name.as_str()).collect();
        assert!(names[0].starts_with("mouse") && names[1].starts_with("event"));
        let vars = dev.vars();
        assert_eq!(vars[0], "PRODUCT=3/1/1/1");
        assert_eq!(vars[1], "NAME=\"virtual-device-ltp\"");
        assert_eq!(&vars[2..6], ["PROP=0", "EV=7", "KEY=10000 0 0 0 0", "REL=3"]);
        assert_eq!(vars[6], "MODALIAS=input:b0003v0001p0001e0001-e0,1,2,k110,r0,1,amlsfw");
        let text = proc_devices();
        assert!(text.contains(&format!("S: Sysfs=/devices/virtual/input/input{number}\n")));
        assert!(text.contains(&format!("H: Handlers={} {} \n", names[0], names[1])));
        let info = InputDevice::handler_info(&dev.handlers[0]);
        let want = format!("/devices/virtual/input/input{number}/{}", names[0]);
        assert_eq!(uevent::devpath(&info), want);
        let name = format!("input{number}");
        let files = sysfs(&[name.as_str()]).unwrap();
        assert!(files.contains(&file("name", String::from("virtual-device-ltp\n"))));
        unregister(number);
        assert!(sysfs(&[name.as_str()]).is_none());
    }
}
