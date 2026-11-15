use crate::buf::NetBuf;
use crate::dev;
use crate::ether::{EthHeader, MacAddr};
use crate::ns;
use crate::tun::{
    IFF_ATTACH_QUEUE, IFF_DETACH_QUEUE, IFF_MULTI_QUEUE, IFF_NO_PI, IFF_TAP, IFF_TUN, IFF_VNET_HDR,
    MAX_TAP_QUEUES, TunFile, flow_hash,
};
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;
use rk_abi::Errno;
use rk_abi::native::if_ether::ETH_P_IP;
use rk_abi::native::poll::{POLLERR, POLLOUT, POLLWRNORM};

/// An IPv4 UDP frame from `src:sport` to `dst:dport`, with an Ethernet header.
fn udp(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16) -> NetBuf {
    let mut ip = [0u8; 28];
    ip[0] = 0x45;
    ip[9] = 17;
    ip[12..16].copy_from_slice(&src);
    ip[16..20].copy_from_slice(&dst);
    ip[20..22].copy_from_slice(&sport.to_be_bytes());
    ip[22..24].copy_from_slice(&dport.to_be_bytes());
    let mut b = NetBuf::from_slice(&ip);
    EthHeader { dst: MacAddr::ZERO, src: MacAddr::ZERO, ethertype: ETH_P_IP as u16 }.push(&mut b);
    b
}

/// The count of the frames in the queue of each file.
fn counts(files: &[TunFile]) -> Vec<usize> {
    files.iter().map(|f| f.queue.out.lock().len()).collect()
}

#[test]
fn the_flow_hash_is_the_same_in_the_two_directions() {
    let a = udp([10, 0, 0, 1], [10, 0, 0, 2], 1000, 53);
    let b = udp([10, 0, 0, 2], [10, 0, 0, 1], 53, 1000);
    let c = udp([10, 0, 0, 1], [10, 0, 0, 2], 1001, 53);
    assert_eq!(flow_hash(a.data()), flow_hash(b.data()));
    assert_ne!(flow_hash(a.data()), flow_hash(c.data()));
    assert_eq!(flow_hash(&[0u8; 10]), 0);
}

// The devices are global, so one test does all of the checks of the queues.
#[test]
fn multi_queue_devices_spread_frames_and_detach_queues() {
    let _serial = crate::TEST_DEVICES.lock();
    dev::init();
    let net = ns::new().unwrap();
    let _in = ns::enter(&net);
    let mq = IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE;

    // `TUNSETIFINDEX` gives the index of the new device.
    let files: Vec<TunFile> = (0..3).map(|_| TunFile::new(net.clone())).collect();
    files[0].ifindex.store(7, Ordering::Relaxed);
    assert_eq!(files[0].set_iff("mq0", mq).unwrap(), "mq0");
    let dev = dev::by_name("mq0").unwrap();
    assert_eq!(dev.ifindex(), 7);
    // A second device with the same index gives `EBUSY`.
    let other = TunFile::new(net.clone());
    other.ifindex.store(7, Ordering::Relaxed);
    assert_eq!(other.set_iff("mq1", mq).err(), Some(Errno::EBUSY));
    assert!(dev::by_name("mq1").is_none());

    // The flag of more than one queue must be the same as the flag of the device.
    assert_eq!(files[1].set_iff("mq0", IFF_TUN | IFF_NO_PI).err(), Some(Errno::EINVAL));
    files[1].set_iff("mq0", mq).unwrap();
    files[2].set_iff("mq0", mq).unwrap();
    dev.set_up(true);
    for port in 0..64 {
        dev.transmit(udp([10, 0, 0, 1], [10, 0, 0, 2], 1000 + port, 53)).unwrap();
    }
    let c = counts(&files);
    assert_eq!(c.iter().sum::<usize>(), 64);
    assert!(c.iter().all(|&n| n > 0), "{c:?}");
    // The frames of one flow go to one queue.
    for f in &files {
        f.queue.out.lock().clear();
    }
    for _ in 0..8 {
        dev.transmit(udp([10, 0, 0, 1], [10, 0, 0, 2], 4000, 53)).unwrap();
    }
    assert_eq!(counts(&files).iter().filter(|&&n| n == 8).count(), 1);
    for f in &files {
        f.queue.out.lock().clear();
    }

    // A detached queue gets no frames, and its file gives `EBADFD`.
    assert_eq!(files[1].set_queue(IFF_ATTACH_QUEUE).err(), Some(Errno::EINVAL));
    files[1].set_queue(IFF_DETACH_QUEUE).unwrap();
    assert_eq!(files[1].device().err(), Some(Errno::EBADFD));
    assert_eq!(files[1].set_queue(IFF_DETACH_QUEUE).err(), Some(Errno::EINVAL));
    assert_eq!(files[1].set_queue(0).err(), Some(Errno::EINVAL));
    for port in 0..32 {
        dev.transmit(udp([10, 0, 0, 1], [10, 0, 0, 2], 1000 + port, 53)).unwrap();
    }
    let c = counts(&files);
    assert_eq!((c[1], c[0] + c[2]), (0, 32));
    files[1].set_queue(IFF_ATTACH_QUEUE).unwrap();
    assert!(files[1].device().is_ok());

    // The device goes away with its last file.
    drop(other);
    drop(files);
    assert!(dev::by_name("mq0").is_none());

    // A device with one queue takes one file.
    let a = TunFile::new(net.clone());
    let b = TunFile::new(net.clone());
    a.set_iff("sq0", IFF_TUN | IFF_NO_PI).unwrap();
    assert_eq!(b.set_iff("sq0", IFF_TUN | IFF_NO_PI).err(), Some(Errno::EBUSY));
    assert_eq!(a.set_queue(IFF_DETACH_QUEUE).err(), Some(Errno::EINVAL));
    drop(a);
    assert!(dev::by_name("sq0").is_none());
    drop(b);

    // A device takes at most `MAX_TAP_QUEUES` queues.
    let many: Vec<TunFile> = (0..=MAX_TAP_QUEUES).map(|_| TunFile::new(net.clone())).collect();
    for f in &many[..MAX_TAP_QUEUES] {
        f.set_iff("big0", mq).unwrap();
    }
    assert_eq!(many[MAX_TAP_QUEUES].set_iff("big0", mq).err(), Some(Errno::E2BIG));
    drop(many);
    assert!(dev::by_name("big0").is_none());
    drop(_in);
    drop(net);
}

#[test]
fn a_detached_file_makes_its_device_persistent() {
    let _serial = crate::TEST_DEVICES.lock();
    dev::init();
    let net = ns::new().unwrap();
    let _in = ns::enter(&net);
    // A file without a device has nothing to change.
    let f = TunFile::new(net.clone());
    assert_eq!(f.set_persist(true).err(), Some(Errno::EBADFD));
    assert_eq!(f.poll_mask(), POLLERR);
    // As systemd-networkd with `MultiQueue=yes`: `TUNSETIFF`, `TUNSETQUEUE` with
    // `IFF_DETACH_QUEUE`, `TUNSETPERSIST`, and then the close of the file.
    f.set_iff("pq0", IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE).unwrap();
    let dev = dev::by_name("pq0").unwrap();
    assert!(dev.carrier());
    f.set_queue(IFF_DETACH_QUEUE).unwrap();
    assert_eq!(f.device().err(), Some(Errno::EBADFD));
    // A detached file can be written, as `tun_chr_poll` of Linux. systemd closes a file of its fd
    // store that gives `POLLERR`.
    assert_eq!(f.poll_mask(), POLLOUT | POLLWRNORM);
    f.set_persist(true).unwrap();
    // The detached file still holds the device, so the carrier stays on until the close.
    assert!(dev.carrier());
    drop(f);
    assert!(!dev.carrier());
    // A new file on the device brings the carrier back.
    let g = TunFile::new(net.clone());
    g.set_iff("pq0", IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE).unwrap();
    assert!(dev.carrier());
    drop(g);
    assert!(!dev.carrier());
    dev::unregister(&dev);
    assert!(dev::by_name("pq0").is_none());
}

#[test]
fn a_device_has_tun_flags_owner_and_group_in_sysfs() {
    let _serial = crate::TEST_DEVICES.lock();
    dev::init();
    let net = ns::new().unwrap();
    let _in = ns::enter(&net);
    // As the TAP device of `NetworkdNetDevTests.test_tuntap`: `ip tuntap show` prints
    // "tap pi multi_queue vnet_hdr" from `tun_flags`.
    let f = TunFile::new(net.clone());
    f.set_iff("mqtap0", IFF_TAP | IFF_VNET_HDR | IFF_MULTI_QUEUE).unwrap();
    let dev = dev::by_name("mqtap0").unwrap();
    assert_eq!(
        dev.driver().sysfs_files(),
        [
            ("group", String::from("-1\n")),
            ("owner", String::from("-1\n")),
            ("tun_flags", String::from("0x4102\n")),
        ]
    );
    // A device of another driver adds no file.
    let d = crate::dummy::create(Some(b"sdum0"), None).unwrap();
    assert!(d.driver().sysfs_files().is_empty());
    dev::unregister(&d);
    drop(f);
    assert!(dev::by_name("mqtap0").is_none());
    drop(_in);
    drop(net);
}
