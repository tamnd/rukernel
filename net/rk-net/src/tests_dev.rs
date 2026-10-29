use crate::arp::{self, ArpPacket};
use crate::buf::{HEADROOM, NetBuf};
use crate::consts::{ARPOP_REPLY, IFF_LOOPBACK, IFF_LOWER_UP, IFF_RUNNING, IFF_UP};
use crate::dev::{self, LinkKind, NetDriver};
use crate::ether::{EthHeader, HLEN, MacAddr};
use alloc::sync::Arc;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_abi::native::if_ether::{ETH_P_ARP, ETH_P_IP};

const MAC: MacAddr = MacAddr([0x52, 0x54, 0, 0x12, 0x34, 0x56]);
const GATEWAY: MacAddr = MacAddr([0x52, 0x55, 10, 0, 2, 2]);

#[test]
fn push_and_pull_move_the_start_of_the_data() {
    let mut b = NetBuf::new(HEADROOM, 64);
    b.extend_from_slice(b"payload");
    b.push(4).copy_from_slice(b"tcp:");
    b.push(3).copy_from_slice(b"ip:");
    assert_eq!(b.data(), b"ip:tcp:payload");
    assert_eq!(b.headroom(), HEADROOM - 7);
    assert_eq!(b.pull(3), Some(&b"ip:"[..]));
    assert_eq!(b.pull(4), Some(&b"tcp:"[..]));
    assert_eq!(b.pull(8), None);
    assert_eq!(b.data(), b"payload");
}

#[test]
fn push_grows_a_buffer_without_headroom() {
    let mut b = NetBuf::from_slice(b"data");
    assert_eq!(b.headroom(), 0);
    b.push(2).copy_from_slice(b"h:");
    assert_eq!(b.data(), b"h:data");
    assert_eq!(b.headroom(), HEADROOM);
}

#[test]
fn put_and_trim_change_the_end_of_the_data() {
    let mut b = NetBuf::new(0, 4);
    b.extend_from_slice(b"abcd");
    assert_eq!(b.tailroom(), 0);
    b.put(2);
    assert_eq!(b.data(), b"abcd\0\0");
    b.trim(3);
    assert_eq!(b.data(), b"abc");
    // The bytes after a trim are zeros again after a put.
    assert_eq!(b.put(2), &[0, 0]);
    b.trim(10);
    assert_eq!(b.len(), 5);
}

#[test]
fn the_ethernet_header_is_in_network_byte_order() {
    let h = EthHeader { dst: MacAddr::BROADCAST, src: MAC, ethertype: ETH_P_IP as u16 };
    let bytes = h.to_bytes();
    assert_eq!(&bytes[12..], &[0x08, 0x00]);
    assert_eq!(EthHeader::parse(&bytes), Some(h));
    assert_eq!(EthHeader::parse(&bytes[..13]), None);
    let mut b = NetBuf::from_slice(b"x");
    h.push(&mut b);
    assert_eq!(b.len(), HLEN + 1);
    b.protocol = 0;
    assert_eq!(EthHeader::pull(&mut b), Some(h));
    assert_eq!((b.data(), u32::from(b.protocol)), (&b"x"[..], ETH_P_IP));
}

#[test]
fn a_mac_address_prints_as_ip_link_does() {
    assert_eq!(alloc::format!("{MAC}"), "52:54:00:12:34:56");
    assert!(MacAddr::BROADCAST.is_broadcast() && MacAddr::BROADCAST.is_multicast());
    assert!(!MAC.is_multicast());
}

#[test]
fn an_arp_request_has_the_layout_of_rfc_826() {
    let frame = ArpPacket::request(MAC, [10, 0, 2, 15], [10, 0, 2, 2]).to_frame(MacAddr::BROADCAST);
    let d = frame.data();
    assert_eq!(d.len(), HLEN + arp::LEN);
    assert_eq!(&d[..6], &[0xff; 6]);
    assert_eq!(&d[12..14], &[0x08, 0x06]);
    // Ethernet, IPv4, the lengths 6 and 4, and the operation 1.
    assert_eq!(&d[14..22], &[0, 1, 0x08, 0, 6, 4, 0, 1]);
    assert_eq!(&d[38..42], &[10, 0, 2, 2]);
}

#[test]
fn an_arp_reply_parses() {
    // The reply of the user network of QEMU to the request above.
    let reply = ArpPacket {
        op: ARPOP_REPLY,
        sender_mac: GATEWAY,
        sender_ip: [10, 0, 2, 2],
        target_mac: MAC,
        target_ip: [10, 0, 2, 15],
    };
    let mut frame = reply.to_frame(MAC);
    // A short frame has padding to 60 bytes.
    frame.put(60 - frame.len());
    let h = EthHeader::pull(&mut frame).unwrap();
    assert_eq!(u32::from(h.ethertype), ETH_P_ARP);
    let p = ArpPacket::parse(frame.data()).unwrap();
    assert_eq!(p, reply);
    assert!(p.is_reply());
    let mut bad = reply.to_bytes();
    bad[5] = 16;
    assert_eq!(ArpPacket::parse(&bad), None);
    assert_eq!(ArpPacket::parse(&reply.to_bytes()[..27]), None);
}

/// A driver that keeps the frames that it sends.
struct Sink {
    sent: rk_frame::sync::SpinLock<Vec<NetBuf>>,
}

impl Default for Sink {
    fn default() -> Self {
        Self { sent: rk_frame::sync::SpinLock::new(Vec::new()) }
    }
}

impl NetDriver for Sink {
    fn kind(&self) -> LinkKind {
        LinkKind::Ether
    }
    fn mac(&self) -> MacAddr {
        MAC
    }
    fn link_up(&self) -> bool {
        false
    }
    fn transmit(&self, frame: NetBuf) -> rk_vfs::inode::Result<()> {
        self.sent.lock().push(frame);
        Ok(())
    }
    fn poll(&self, _budget: usize, _deliver: &mut dyn FnMut(NetBuf)) -> usize {
        0
    }
}

// The devices are global, so one test does all of the checks of the registration.
#[test]
fn devices_get_names_indexes_and_counts() {
    let _serial = crate::TEST_DEVICES.lock();
    dev::init();
    dev::init();
    let lo = dev::by_name("lo").unwrap();
    assert_eq!((lo.ifindex(), lo.kind(), lo.mtu()), (1, LinkKind::Loopback, 65536));
    assert_eq!(lo.flags(), IFF_LOOPBACK);
    let sink = Arc::new(Sink::default());
    let eth0 = dev::register(sink.clone()).unwrap();
    let eth1 = dev::register(Arc::new(Sink::default())).unwrap();
    assert_eq!((eth0.name().as_str(), eth0.ifindex()), ("eth0", 2));
    assert_eq!((eth1.name().as_str(), eth1.ifindex()), ("eth1", 3));
    assert_eq!(dev::by_index(3).unwrap().name(), "eth1");
    assert_eq!(dev::devices().len(), 3);
    assert_eq!(dev::register(Arc::new(dev::Loopback::default())).err(), Some(Errno::EEXIST));

    // A device that is down sends nothing.
    let arp = ArpPacket::request(MAC, [10, 0, 2, 15], [10, 0, 2, 2]);
    assert_eq!(eth0.transmit(arp.to_frame(MacAddr::BROADCAST)), Err(Errno::ENETDOWN));
    eth0.set_up(true);
    assert_eq!(eth0.flags() & (IFF_UP | IFF_RUNNING), IFF_UP);
    eth0.transmit(arp.to_frame(MacAddr::BROADCAST)).unwrap();
    let mut big = NetBuf::zeroed(HLEN + 1501);
    assert_eq!(eth0.transmit(big.clone()), Err(Errno::EMSGSIZE));
    big.trim(HLEN + 1500);
    eth0.transmit(big).unwrap();
    assert_eq!(sink.sent.lock().len(), 2);
    let s = eth0.stats();
    assert_eq!((s.tx_packets, s.tx_bytes, s.tx_dropped), (2, 42 + 1514, 2));

    // The loopback device gives back each frame that it sends.
    lo.set_up(true);
    assert_eq!(lo.flags(), IFF_LOOPBACK | IFF_LOWER_UP | IFF_UP | IFF_RUNNING);
    for k in 0..3u8 {
        lo.transmit(NetBuf::from_slice(&[k; 20])).unwrap();
    }
    let mut got = Vec::new();
    assert_eq!(lo.poll(2, &mut |d, b| got.push((d.ifindex(), b))), 2);
    assert_eq!(lo.poll(8, &mut |d, b| got.push((d.ifindex(), b))), 1);
    assert!(
        got.iter()
            .enumerate()
            .all(|(k, (i, b))| *i == 1 && b.ifindex == 1 && b.data() == [k as u8; 20])
    );
    let s = lo.stats();
    assert_eq!((s.tx_packets, s.rx_packets, s.rx_bytes), (3, 3, 60));
}

/// A packet socket of a device that goes down gets `ENETDOWN` once, and a send after the device
/// goes away gives `ENXIO`, as `packet_notifier` of Linux.
#[test]
fn a_packet_socket_sees_its_device_go_down() {
    use crate::packet::{AF_PACKET, PacketSocket};
    use crate::{Message, NoPaths, Socket};
    use rk_abi::native::socket::{SO_ERROR, SOL_SOCKET};

    let _serial = crate::TEST_DEVICES.lock();
    dev::init();
    let d = crate::dummy::create(Some(b"pkdown0")).unwrap();
    d.set_up(true);
    let protocol = (ETH_P_IP as u16).to_be();
    let p = PacketSocket::new(crate::consts::SOCK_RAW, u32::from(protocol)).unwrap();
    let mut addr = [0u8; 20];
    addr[..2].copy_from_slice(&(AF_PACKET as u16).to_ne_bytes());
    addr[2..4].copy_from_slice(&protocol.to_ne_bytes());
    addr[4..8].copy_from_slice(&d.ifindex().to_ne_bytes());
    p.bind(&NoPaths, &addr).unwrap();
    d.set_up(false);
    assert_eq!(p.recv(64, 0, true).err(), Some(Errno::ENETDOWN));
    assert_eq!(p.recv(64, 0, true).err(), Some(Errno::EAGAIN));
    // `SO_ERROR` gives the error and clears it.
    d.set_up(true);
    d.set_up(false);
    let err = |p: &PacketSocket| p.get_option(SOL_SOCKET, SO_ERROR).unwrap();
    assert_eq!(err(&p), i32::from(Errno::ENETDOWN.get()).to_ne_bytes());
    assert_eq!(err(&p), 0i32.to_ne_bytes());
    dev::unregister(&d);
    let msg = Message { data: alloc::vec![0; HLEN], ..Message::default() };
    assert_eq!(p.send(&NoPaths, msg, 0, true).err(), Some(Errno::ENXIO));
}

/// `PACKET_VERSION` takes `TPACKET_V1` only, because there are no mapped rings.
#[test]
fn a_packet_socket_takes_only_the_first_ring_version() {
    use crate::Socket;
    use crate::packet::{PacketSocket, SOL_PACKET};

    let p = PacketSocket::new(crate::consts::SOCK_RAW, 0).unwrap();
    assert_eq!(p.set_option(SOL_PACKET, 10, &0i32.to_ne_bytes()), Ok(()));
    assert_eq!(p.set_option(SOL_PACKET, 10, &2i32.to_ne_bytes()), Err(Errno::EINVAL));
    assert_eq!(p.set_option(SOL_PACKET, 10, &[0u8; 2]), Err(Errno::EINVAL));
    assert_eq!(p.get_option(SOL_PACKET, 10), Ok(0i32.to_ne_bytes().to_vec()));
}
