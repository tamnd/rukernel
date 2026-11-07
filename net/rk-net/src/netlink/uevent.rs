//! The protocol `NETLINK_KOBJECT_UEVENT`, as lib/kobject_uevent.c of Linux.
//!
//! A socket of this protocol in the group 1 gets the events of the devices that
//! `rk_vfs::uevent` makes. The event of a character or block device goes to the sockets of all
//! namespaces, as `uevent_net_broadcast_untagged` of Linux. The event of a network device and of
//! its queues goes only to the sockets of the namespace of the device, as
//! `uevent_net_broadcast_tagged`.

use super::broadcast;
use crate::dev::{self, NetDevice};
use crate::ns;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_abi::native::netlink::NETLINK_KOBJECT_UEVENT;
use rk_frame::sync::SpinLock;
use rk_vfs::cred::{self, cap};
use rk_vfs::inode::Result;
use rk_vfs::uevent::{self, Action, Event};

/// The number of groups of the protocol. Linux gives each protocol at least 32 groups.
pub const NGROUPS: u32 = 32;

/// The group of the events of the kernel. udev sends its own events to the group 2.
const GROUP: u32 = 1;

/// Sends the datagram `msg` to the sockets of the current namespace in the group 1.
fn send_here(msg: &[u8]) {
    broadcast(NETLINK_KOBJECT_UEVENT, None, msg, 0, 0, GROUP, super::Creds::KERNEL);
}

/// Sends the datagram `msg` to the sockets of each namespace.
fn send_all(msg: Vec<u8>) {
    for index in ns::indices() {
        let _in = ns::enter_index(index);
        send_here(&msg);
    }
}

/// The names of the network devices, by the address of the device, for the path before a change
/// of the name.
static NAMES: SpinLock<BTreeMap<usize, String>> = SpinLock::new(BTreeMap::new());

fn key(d: &NetDevice) -> usize {
    core::ptr::from_ref(d) as usize
}

/// The path of the network device `d` with the name `name` in sysfs, below `/sys`. An interface
/// of a virtio device is in `VIRTIO/net/NAME`, where `VIRTIO` is the directory of the virtio
/// device, as on Linux. Another interface is in `/devices/virtual/net/NAME`.
#[must_use]
pub fn path(d: &NetDevice, name: &str) -> String {
    let parent = d.parent().filter(|(_, bus)| *bus == "virtio");
    match parent.and_then(|(p, _)| rk_vfs::bus::virtio_named(&p)) {
        Some(parent) => format!("{parent}/net/{name}"),
        None => format!("/devices/virtual/net/{name}"),
    }
}

/// The event `action` of the network device `d`, with the variables of `netdev_uevent` of
/// Linux. `old` is the old path for the event `move`.
fn net_event(d: &NetDevice, action: Action, old: Option<&str>) -> Event {
    let name = d.name();
    let mut e = Event::new(action, path(d, &name), "net");
    if let Some(old) = old {
        e.add(format!("DEVPATH_OLD={old}"));
    }
    // tun.c of Linux gives its devices the device type `tun`.
    if d.link_kind() == Some(crate::tun::KIND) {
        e.add(String::from("DEVTYPE=tun"));
    }
    e.add(format!("INTERFACE={name}"));
    e.add(format!("IFINDEX={}", d.ifindex()));
    e
}

/// Sends the events of the queues of `d`: `rx-0` and then `tx-0`, as `register_queue_kobjects`
/// and `remove_queue_kobjects` of Linux.
fn queue_events(d: &NetDevice, action: Action) {
    for q in ["rx-0", "tx-0"] {
        let queue = format!("{}/queues/{q}", path(d, &d.name()));
        send_here(&Event::new(action, queue, "queues").finish());
    }
}

/// Sends the events of a network device, as `netdev_register_kobject`,
/// `netdev_unregister_kobject` and `device_rename` of Linux. It runs in the namespace of the
/// device. A move to another namespace is a remove in the old one and an add in the new one.
fn netdev_event(d: &NetDevice, event: dev::Event) {
    match event {
        dev::Event::Register => {
            NAMES.lock().insert(key(d), d.name());
            send_here(&net_event(d, Action::Add, None).finish());
            queue_events(d, Action::Add);
        }
        dev::Event::Unregister => {
            queue_events(d, Action::Remove);
            send_here(&net_event(d, Action::Remove, None).finish());
            NAMES.lock().remove(&key(d));
        }
        dev::Event::Name => {
            let old = NAMES.lock().insert(key(d), d.name());
            if let Some(old) = old {
                send_here(&net_event(d, Action::Move, Some(&path(d, &old))).finish());
            }
        }
        _ => {}
    }
}

/// Sends the event `action` that a process asks for with a write to the file `uevent` of the
/// network device `d`, as `uevent_store` of Linux. `vars` come from `rk_vfs::uevent::parse_synth`,
/// before the variables of the device. It runs in the namespace of the device.
pub fn synth(d: &NetDevice, action: Action, vars: Vec<String>) {
    let mut e = net_event(d, action, None);
    e.vars.splice(0..0, vars);
    send_here(&e.finish());
}

/// Runs a message that a process sends to the kernel, as `uevent_net_rcv_skb` of Linux. A
/// process with `CAP_SYS_ADMIN` can send an event to the sockets of its namespace. The event gets
/// the next sequence number at its end.
pub(super) fn rcv(m: &[u8]) -> Result<()> {
    if !cred::current().capable(cap::SYS_ADMIN) {
        return Err(Errno::EPERM);
    }
    let mut msg = m.to_vec();
    let n = uevent::next_seqnum();
    msg.extend_from_slice(format!("SEQNUM={n}").as_bytes());
    msg.push(0);
    send_here(&msg);
    Ok(())
}

/// Starts the events: the sink of the events of the devices and the notifier of the network
/// devices. The devices that exist now get no event.
pub(super) fn init() {
    for d in dev::all_devices() {
        NAMES.lock().insert(key(&d), d.name());
    }
    uevent::set_sink(send_all);
    dev::add_notifier(netdev_event);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consts::SOCK_RAW;
    use crate::netlink::{NetlinkSocket, sockaddr};
    use crate::{NoPaths, Socket};
    use alloc::sync::Arc;
    use rk_abi::native::netlink::NETLINK_ROUTE;

    fn listener(protocol: u32) -> Arc<NetlinkSocket> {
        let s = NetlinkSocket::new(SOCK_RAW, protocol).unwrap();
        s.bind(&NoPaths, &sockaddr(0, 1)).unwrap();
        s
    }

    /// The events that `s` got with `text` in the first string.
    fn got(s: &NetlinkSocket, text: &str) -> Vec<Vec<String>> {
        let mut out = Vec::new();
        while let Ok(r) = s.recv(65536, 0, true) {
            let data = r.data.strip_suffix(&[0]).unwrap_or(&r.data);
            let strings: Vec<String> =
                data.split(|&b| b == 0).map(|s| String::from_utf8_lossy(s).into_owned()).collect();
            if strings[0].contains(text) {
                out.push(strings);
            }
        }
        out
    }

    #[test]
    fn a_device_event_goes_to_the_uevent_sockets_of_each_namespace() {
        let _serial = crate::TEST_DEVICES.lock();
        dev::init();
        let other = ns::new().unwrap();
        let here = listener(NETLINK_KOBJECT_UEVENT);
        let route = listener(NETLINK_ROUTE);
        let there = {
            let _in = ns::enter(&other);
            listener(NETLINK_KOBJECT_UEVENT)
        };
        let e = Event::new(Action::Change, String::from("/devices/virtual/block/uevblk7"), "block");
        send_all(e.finish());
        for s in [&here, &there] {
            let events = got(s, "uevblk7");
            assert_eq!(events.len(), 1);
            assert_eq!(events[0][0], "change@/devices/virtual/block/uevblk7");
            assert_eq!(events[0][1], "ACTION=change");
            assert!(events[0][4].starts_with("SEQNUM="));
        }
        assert!(got(&route, "uevblk7").is_empty());
    }

    #[test]
    fn a_network_device_event_goes_only_to_its_namespace() {
        let _serial = crate::TEST_DEVICES.lock();
        dev::init();
        crate::netlink::init();
        let other = ns::new().unwrap();
        let here = listener(NETLINK_KOBJECT_UEVENT);
        let (there, d) = {
            let _in = ns::enter(&other);
            let s = listener(NETLINK_KOBJECT_UEVENT);
            (s, crate::dummy::create(Some(b"uev9")).unwrap())
        };
        {
            let _in = ns::enter(&other);
            d.set_name(b"uev8").unwrap();
            dev::unregister(&d);
        }
        assert!(got(&here, "uev").is_empty());
        let events: Vec<String> = got(&there, "uev").into_iter().map(|e| e[0].clone()).collect();
        assert_eq!(
            events,
            [
                "add@/devices/virtual/net/uev9",
                "add@/devices/virtual/net/uev9/queues/rx-0",
                "add@/devices/virtual/net/uev9/queues/tx-0",
                "move@/devices/virtual/net/uev8",
                "remove@/devices/virtual/net/uev8/queues/rx-0",
                "remove@/devices/virtual/net/uev8/queues/tx-0",
                "remove@/devices/virtual/net/uev8",
            ]
        );
        let _in = ns::enter(&other);
        let d2 = crate::dummy::create(Some(b"uev7")).unwrap();
        let add = got(&there, "uev7").remove(0);
        assert_eq!(add[3], "SUBSYSTEM=net");
        assert_eq!(add[4], "INTERFACE=uev7");
        assert_eq!(add[5], format!("IFINDEX={}", d2.ifindex()));
        dev::unregister(&d2);
    }

    #[test]
    fn a_socket_with_so_passcred_gets_the_credentials_of_the_sender() {
        use crate::{Cred, Message};
        use rk_abi::native::socket::{SO_PASSCRED, SOL_SOCKET};
        let _serial = crate::TEST_DEVICES.lock();
        // The udev monitor of systemd sets `SO_PASSCRED` and refuses an event without the
        // credentials of the sender.
        let s = listener(NETLINK_KOBJECT_UEVENT);
        assert_eq!(s.get_option(SOL_SOCKET, SO_PASSCRED).unwrap(), 0i32.to_ne_bytes());
        s.set_option(SOL_SOCKET, SO_PASSCRED, &1i32.to_ne_bytes()).unwrap();
        assert_eq!(s.get_option(SOL_SOCKET, SO_PASSCRED).unwrap(), 1i32.to_ne_bytes());
        assert_eq!(s.set_option(SOL_SOCKET, SO_PASSCRED, &[1]), Err(Errno::EINVAL));
        // An event of the kernel has the process ID 0, the user 0 and the group 0.
        send_all(
            Event::new(Action::Add, String::from("/devices/virtual/block/uevcred1"), "block")
                .finish(),
        );
        let r = s.recv(65536, 0, true).unwrap();
        let c = r.cred.unwrap();
        assert_eq!((c.pid, c.uid, c.gid), (0, 0, 0));
        // A datagram of a process has the credentials of `SCM_CREDENTIALS`.
        let from = listener(NETLINK_KOBJECT_UEVENT);
        let cred = Cred { pid: 42, uid: 1000, gid: 100, process: None };
        let m = Message {
            data: b"x".to_vec(),
            addr: Some(sockaddr(s.portid(), 0)),
            cred: Some(cred),
            ..Message::default()
        };
        from.send(&NoPaths, m, 0, true).unwrap();
        let r = s.recv(65536, 0, true).unwrap();
        assert_eq!(r.data, b"x");
        let c = r.cred.unwrap();
        assert_eq!((c.pid, c.uid, c.gid), (42, 1000, 100));
        s.set_option(SOL_SOCKET, SO_PASSCRED, &0i32.to_ne_bytes()).unwrap();
        assert_eq!(s.get_option(SOL_SOCKET, SO_PASSCRED).unwrap(), 0i32.to_ne_bytes());
    }

    #[test]
    fn the_filter_of_a_socket_drops_the_events_that_it_does_not_take() {
        use crate::filter::Insn;
        use rk_abi::native::socket::{
            SO_ATTACH_FILTER, SO_DETACH_FILTER, SO_LOCK_FILTER, SOL_SOCKET,
        };
        let _serial = crate::TEST_DEVICES.lock();
        let s = listener(NETLINK_KOBJECT_UEVENT);
        // ldb [0]; jeq #'a', drop, keep: the filter drops the events with the action `add`.
        let prog: Vec<u8> = [
            Insn { code: 0x30, jt: 0, jf: 0, k: 0 },
            Insn { code: 0x15, jt: 0, jf: 1, k: u32::from(b'a') },
            Insn { code: 0x06, jt: 0, jf: 0, k: 0 },
            Insn { code: 0x06, jt: 0, jf: 0, k: u32::MAX },
        ]
        .into_iter()
        .flat_map(Insn::to_bytes)
        .collect();
        s.set_option(SOL_SOCKET, SO_ATTACH_FILTER, &prog).unwrap();
        let path = String::from("/devices/virtual/block/uevflt1");
        send_all(Event::new(Action::Add, path.clone(), "block").finish());
        send_all(Event::new(Action::Change, path.clone(), "block").finish());
        let events: Vec<String> = got(&s, "uevflt1").into_iter().map(|e| e[0].clone()).collect();
        assert_eq!(events, ["change@/devices/virtual/block/uevflt1"]);
        // A locked filter stays. Without it, each event comes again.
        s.set_option(SOL_SOCKET, SO_LOCK_FILTER, &1i32.to_ne_bytes()).unwrap();
        assert_eq!(s.get_option(SOL_SOCKET, SO_LOCK_FILTER).unwrap(), 1i32.to_ne_bytes());
        assert_eq!(s.set_option(SOL_SOCKET, SO_DETACH_FILTER, &[]), Err(Errno::EPERM));
        let open = listener(NETLINK_KOBJECT_UEVENT);
        open.set_option(SOL_SOCKET, SO_ATTACH_FILTER, &prog).unwrap();
        open.set_option(SOL_SOCKET, SO_DETACH_FILTER, &[]).unwrap();
        assert_eq!(open.set_option(SOL_SOCKET, SO_DETACH_FILTER, &[]), Err(Errno::ENOENT));
        send_all(Event::new(Action::Add, path, "block").finish());
        assert_eq!(got(&open, "uevflt1").len(), 1);
    }
}
