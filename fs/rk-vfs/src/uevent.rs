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

use crate::device::{DeviceInfo, major, minor};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
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
/// `/devices/virtual/CLASS/NAME`, where `NAME` is the last part of the name in `/dev`.
pub fn devpath(d: &DeviceInfo) -> String {
    let name = d.name.rsplit('/').next().unwrap_or(&d.name);
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
    fn the_actions_have_the_names_of_linux() {
        for a in Action::ALL {
            assert_eq!(Action::from_name(a.name().as_bytes()), Some(a));
        }
        assert_eq!(Action::from_name(b"bad"), None);
    }
}
