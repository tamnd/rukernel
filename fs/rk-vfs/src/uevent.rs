//! The events of the devices for user space, as lib/kobject_uevent.c of Linux.
//!
//! When a device comes, goes or changes, the kernel sends an event to the sockets of the protocol
//! `NETLINK_KOBJECT_UEVENT` that are in the group 1. udev and mdev read the events. An event is a
//! datagram of strings, each with a 0 at the end: first `ACTION@DEVPATH`, then the variables
//! `ACTION`, `DEVPATH`, `SUBSYSTEM`, the variables of the device and `SEQNUM`. Each event gets the
//! next sequence number, also when no socket gets it. `/sys/kernel/uevent_seqnum` shows the last
//! number.
//!
//! The netlink layer gives the function that sends the datagrams with [`set_sink`]. An event of a
//! character or block device goes to the sockets of all network namespaces. An event of a network
//! device goes only to the sockets of its namespace, and the netlink layer sends it itself.
//!
//! A process can ask for an event with a write to the file `uevent` of a device in sysfs, as
//! `udevadm trigger` does. [`parse_synth`] reads the text of the write.

use crate::Result;
use crate::device::{DeviceInfo, major, minor};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use rk_abi::Errno;
use rk_frame::sync::Once;

/// The action of an event, as `enum kobject_action` of Linux.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// A device comes.
    Add,
    /// A device goes.
    Remove,
    /// A device changes, for example a loop device gets a file.
    Change,
    /// A device gets a new name or a new parent.
    Move,
    /// A device is online again.
    Online,
    /// A device is offline.
    Offline,
    /// A driver takes a device.
    Bind,
    /// A driver lets a device go.
    Unbind,
}

impl Action {
    /// All actions, in the order of `kobject_actions` of Linux.
    pub const ALL: [Self; 8] = [
        Self::Add,
        Self::Remove,
        Self::Change,
        Self::Move,
        Self::Online,
        Self::Offline,
        Self::Bind,
        Self::Unbind,
    ];

    /// The name of the action in an event, for example `add`.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Add => "add",
            Self::Remove => "remove",
            Self::Change => "change",
            Self::Move => "move",
            Self::Online => "online",
            Self::Offline => "offline",
            Self::Bind => "bind",
            Self::Unbind => "unbind",
        }
    }

    /// The action with the name `name`, as `kobject_action_type` of Linux.
    pub fn from_name(name: &[u8]) -> Option<Self> {
        Self::ALL.into_iter().find(|a| a.name().as_bytes() == name)
    }
}

/// An event before it has its sequence number, as `struct kobj_uevent_env` of Linux.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    /// The action.
    pub action: Action,
    /// The path of the device in sysfs, below `/sys`, for example `/devices/virtual/block/loop0`.
    pub devpath: String,
    /// The subsystem, for example `block`, `net` or `queues`.
    pub subsystem: String,
    /// The variables after `SUBSYSTEM`, each as `KEY=VALUE`.
    pub vars: Vec<String>,
}

impl Event {
    /// An event with no variables of the device.
    pub fn new(action: Action, devpath: String, subsystem: &str) -> Self {
        Self { action, devpath, subsystem: String::from(subsystem), vars: Vec::new() }
    }

    /// Adds the variable `var`, as `add_uevent_var` of Linux.
    pub fn add(&mut self, var: String) {
        self.vars.push(var);
    }

    /// Gives the datagram of the event with the sequence number `seqnum`.
    pub fn message(&self, seqnum: u64) -> Vec<u8> {
        let action = self.action.name();
        let mut out = Vec::new();
        let mut push = |s: &str| {
            out.extend_from_slice(s.as_bytes());
            out.push(0);
        };
        push(&format!("{action}@{}", self.devpath));
        push(&format!("ACTION={action}"));
        push(&format!("DEVPATH={}", self.devpath));
        push(&format!("SUBSYSTEM={}", self.subsystem));
        for v in &self.vars {
            push(v);
        }
        push(&format!("SEQNUM={seqnum}"));
        out
    }

    /// Gives the next sequence number and the datagram of the event with it. The caller sends
    /// the datagram.
    pub fn finish(&self) -> Vec<u8> {
        self.message(next_seqnum())
    }
}

/// The number of the last event, `uevent_seqnum` of Linux.
static SEQNUM: AtomicU64 = AtomicU64::new(0);

/// The number of the last event, for `/sys/kernel/uevent_seqnum`.
pub fn seqnum() -> u64 {
    SEQNUM.load(Ordering::Acquire)
}

/// Takes the next sequence number.
pub fn next_seqnum() -> u64 {
    SEQNUM.fetch_add(1, Ordering::AcqRel) + 1
}

/// The function that sends a datagram to the sockets of all network namespaces.
pub type Sink = fn(Vec<u8>);

static SINK: Once<Sink> = Once::new();

/// Sets the function that sends the events to the sockets. Only the first call has an effect.
pub fn set_sink(f: Sink) {
    SINK.call_once(|| f);
}

/// Sends `event` to the sockets of all network namespaces, as `kobject_uevent_env` of Linux.
/// The event takes a sequence number also when no socket gets it.
pub fn send(event: &Event) {
    let msg = event.finish();
    if let Some(sink) = SINK.get() {
        sink(msg);
    }
}

/// The path of the device `d` in sysfs, below `/sys`. sysfs puts each device in
/// `/devices/virtual/CLASS/NAME`, where `NAME` is the last part of the name in `/dev`. A handler
/// of an input device is in the directory of its input device.
pub fn devpath(d: &DeviceInfo) -> String {
    let name = d.name.rsplit('/').next().unwrap_or(&d.name);
    if let Some(parent) = crate::input::parent(d) {
        return format!("{parent}/{name}");
    }
    format!("/devices/virtual/{}/{name}", d.class)
}

/// The event `action` of the device `d` with the variables of `dev_uevent` of Linux: `MAJOR`,
/// `MINOR`, `DEVNAME`, and `DEVTYPE=disk` for a block device. `extra` comes after them.
pub fn device_event(d: &DeviceInfo, action: Action, extra: &[&str]) -> Event {
    let mut e = Event::new(action, devpath(d), d.class);
    e.add(format!("MAJOR={}", major(d.rdev)));
    e.add(format!("MINOR={}", minor(d.rdev)));
    e.add(format!("DEVNAME={}", d.name));
    if d.block {
        e.add(String::from("DEVTYPE=disk"));
    }
    for v in extra {
        e.add(String::from(*v));
    }
    e
}

/// Sends the event `action` of the device `d` to all namespaces.
pub fn device(d: &DeviceInfo, action: Action, extra: &[&str]) {
    send(&device_event(d, action, extra));
}

/// Sends the event `action` that a process asks for with a write to the file `uevent` of the
/// device `d`. `vars` come from [`parse_synth`]. They come before the variables of the device, as
/// the variables of `kobject_uevent_env` of Linux come before the variables of `dev_uevent`.
pub fn synth_device(d: &DeviceInfo, action: Action, vars: Vec<String>) {
    let mut e = device_event(d, action, &[]);
    e.vars.splice(0..0, vars);
    send(&e);
}

/// The length of a UUID as text, `UUID_STRING_LEN` of Linux.
const UUID_LEN: usize = 36;

/// Tells if `s` is a UUID as text, as `uuid_is_valid` of Linux: 32 hexadecimal digits in groups
/// of 8, 4, 4, 4 and 12, with a `-` between the groups.
fn uuid_is_valid(s: &[u8]) -> bool {
    s.len() == UUID_LEN
        && s.iter().enumerate().all(|(i, &c)| {
            if matches!(i, 8 | 13 | 18 | 23) { c == b'-' } else { c.is_ascii_hexdigit() }
        })
}

/// Removes one `\n` or one 0 at the end of `s`, as a write with `echo` adds a `\n`.
fn strip_end(s: &[u8]) -> &[u8] {
    s.strip_suffix(b"\n").or_else(|| s.strip_suffix(b"\0")).unwrap_or(s)
}

/// The bytes `s` as text, or `EINVAL`.
fn as_text(s: &[u8]) -> Result<&str> {
    core::str::from_utf8(s).map_err(|_| Errno::EINVAL)
}

/// Reads the text of a write to the file `uevent` of a device, as `kobject_synth_uevent` of Linux.
/// The text is `ACTION [UUID [KEY=VALUE...]]`, with a space between the words. Gives the action
/// and the variables of the event: `SYNTH_UUID` with the UUID, or `SYNTH_UUID=0` when the text has
/// only the action, and `SYNTH_ARG_KEY=VALUE` for each pair. A key has only letters and digits.
///
/// Gives `EINVAL` for an unknown action, a bad UUID or a bad pair.
pub fn parse_synth(text: &[u8]) -> Result<(Action, Vec<String>)> {
    let text = strip_end(text);
    let (name, args) = match text.iter().position(|&c| c == b' ') {
        Some(i) => (&text[..i], Some(&text[i + 1..])),
        None => (text, None),
    };
    let action = Action::from_name(name).ok_or(Errno::EINVAL)?;
    let Some(args) = args else {
        return Ok((action, Vec::from([String::from("SYNTH_UUID=0")])));
    };
    let args = strip_end(args);
    let (uuid, rest) = args.split_at_checked(UUID_LEN).ok_or(Errno::EINVAL)?;
    if !uuid_is_valid(uuid) {
        return Err(Errno::EINVAL);
    }
    let mut vars = Vec::from([format!("SYNTH_UUID={}", as_text(uuid)?)]);
    if rest.is_empty() {
        return Ok((action, vars));
    }
    // The pairs come after one space at least.
    if rest[0] != b' ' {
        return Err(Errno::EINVAL);
    }
    for pair in rest.split(|&c| c == b' ').filter(|p| !p.is_empty()) {
        let eq = pair.iter().position(|&c| c == b'=').ok_or(Errno::EINVAL)?;
        let (key, value) = (&pair[..eq], &pair[eq + 1..]);
        if key.is_empty() || !key.iter().all(u8::is_ascii_alphanumeric) {
            return Err(Errno::EINVAL);
        }
        vars.push(format!("SYNTH_ARG_{}={}", as_text(key)?, as_text(value)?));
    }
    Ok((action, vars))
}

/// Sends the event `action` of the device with the number `rdev` and the type `block`, if it is
/// in the list of devices.
pub fn device_number(block: bool, rdev: u64, action: Action, extra: &[&str]) {
    let found = crate::device::devices().into_iter().find(|d| d.block == block && d.rdev == rdev);
    if let Some(d) = found {
        device(&d, action, extra);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::makedev;

    fn strings(msg: &[u8]) -> Vec<&str> {
        let msg = msg.strip_suffix(&[0]).unwrap();
        msg.split(|&b| b == 0).map(|s| core::str::from_utf8(s).unwrap()).collect()
    }

    #[test]
    fn a_block_device_event_has_the_variables_of_linux() {
        let d = DeviceInfo {
            name: String::from("loop3"),
            class: "block",
            rdev: makedev(7, 3),
            block: true,
            perm: 0o660,
        };
        let msg = device_event(&d, Action::Change, &[]).message(42);
        assert_eq!(
            strings(&msg),
            [
                "change@/devices/virtual/block/loop3",
                "ACTION=change",
                "DEVPATH=/devices/virtual/block/loop3",
                "SUBSYSTEM=block",
                "MAJOR=7",
                "MINOR=3",
                "DEVNAME=loop3",
                "DEVTYPE=disk",
                "SEQNUM=42",
            ]
        );
    }

    #[test]
    fn a_char_device_has_the_last_part_of_its_name_in_the_path() {
        let d = DeviceInfo {
            name: String::from("net/tun"),
            class: "misc",
            rdev: makedev(10, 200),
            block: false,
            perm: 0o666,
        };
        let e = device_event(&d, Action::Add, &["X=1"]);
        assert_eq!(e.devpath, "/devices/virtual/misc/tun");
        let msg = e.message(1);
        let s = strings(&msg);
        assert_eq!(s[6], "DEVNAME=net/tun");
        assert_eq!(s[7], "X=1");
    }

    #[test]
    fn each_event_takes_the_next_number() {
        let e = Event::new(Action::Add, String::from("/devices/x"), "x");
        let before = seqnum();
        let msg = e.finish();
        assert!(seqnum() > before);
        assert!(strings(&msg).last().unwrap().starts_with("SEQNUM="));
    }

    #[test]
    fn a_write_to_uevent_gives_the_action_and_the_synthetic_variables() {
        let uuid = "01234567-89ab-cdef-0123-456789abcdef";
        assert_eq!(
            parse_synth(b"add\n"),
            Ok((Action::Add, Vec::from([String::from("SYNTH_UUID=0")])))
        );
        let text = format!("change {uuid} A=1 Bb2=two\n");
        let (action, vars) = parse_synth(text.as_bytes()).unwrap();
        assert_eq!(action, Action::Change);
        assert_eq!(
            vars,
            [format!("SYNTH_UUID={uuid}"), "SYNTH_ARG_A=1".into(), "SYNTH_ARG_Bb2=two".into()]
        );
        assert_eq!(parse_synth(format!("remove {uuid}").as_bytes()).unwrap().1.len(), 1);
        for bad in [
            String::from("bad"),
            String::new(),
            String::from("add "),
            String::from("add 0123"),
            format!("add {uuid}X"),
            format!("add {uuid} A"),
            format!("add {uuid} A-B=1"),
            String::from("add 01234567-89ab-cdef-0123-456789abcdeg"),
        ] {
            assert_eq!(parse_synth(bad.as_bytes()), Err(Errno::EINVAL), "{bad}");
        }
    }

    #[test]
    fn the_actions_have_the_names_of_linux() {
        for a in Action::ALL {
            assert_eq!(Action::from_name(a.name().as_bytes()), Some(a));
        }
        assert_eq!(Action::from_name(b"bad"), None);
    }
}
