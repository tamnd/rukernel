use crate::config::{self, IpConfig};
use crate::ipv4::{self, Bad, DF, Header, MF, UdpHeader};
use crate::neigh::{self, Resolve};
use crate::ports::{Binding, EPHEMERAL, Ports};
use crate::route::{IfAddr, Route, Table};
use crate::{Dgram, Proto, checksum, classify, sockaddr};
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_abi::native::inet::{IPPROTO_ICMP, IPPROTO_UDP};
use rk_net::consts::{
    ICMP_ECHO, ICMP_ECHOREPLY, MSG_PEEK, MSG_TRUNC, SOCK_DGRAM, SOCK_RAW, SOCK_SEQPACKET,
    SOCK_STREAM,
};
use rk_net::ether::MacAddr;
use rk_net::{Message, NoPaths, Socket};

#[test]
fn checksum_of_rfc1071_example() {
    let data = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
    assert_eq!(checksum::checksum(&data), !0xddf2);
    // An odd length pads with a zero byte.
    assert_eq!(checksum::checksum(&[0x01]), !0x0100);
    // A buffer with its checksum gives 0.
    let mut d = data.to_vec();
    d.extend_from_slice(&checksum::checksum(&data).to_be_bytes());
    assert_eq!(checksum::checksum(&d), 0);
}

#[test]
fn udp_checksum_is_never_zero() {
    // The sum of this datagram is 0xffff, so the checksum would be 0, which means "none".
    let src = [0, 0, 0, 0];
    let dst = [0, 0, 0, 0];
    let mut d = vec![0u8; 8];
    // The pseudo header adds 17 and 8. The words of the datagram add the rest.
    let rest = 0xffffu32 - 17 - 8 - 8;
    d[0..2].copy_from_slice(&(rest as u16).to_be_bytes());
    d[4..6].copy_from_slice(&8u16.to_be_bytes());
    assert_eq!(checksum::udp(src, dst, &d), 0xffff);
}

const SAMPLE: [u8; 20] = [
    0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0xb8, 0x61, 0xc0, 0xa8, 0x00, 0x01,
    0xc0, 0xa8, 0x00, 0xc7,
];

fn sample_packet() -> Vec<u8> {
    let mut p = SAMPLE.to_vec();
    p.resize(0x73, 0);
    p
}

#[test]
fn header_builds_and_parses() {
    let mut h = Header::new([192, 168, 0, 1], [192, 168, 0, 199], ipv4::PROTO_UDP, 0x73 - 20);
    h.ttl = 64;
    assert_eq!(h.to_bytes(), SAMPLE);
    let p = sample_packet();
    let parsed = Header::parse(&p).unwrap();
    assert_eq!(parsed, h);
    assert_eq!(parsed.frag, DF);
}

#[test]
fn header_checks() {
    let p = sample_packet();
    assert_eq!(Header::parse(&p[..19]), Err(Bad::Header));
    let mut bad = p.clone();
    bad[0] = 0x65;
    assert_eq!(Header::parse(&bad), Err(Bad::Header));
    let mut bad = p.clone();
    bad[0] = 0x44;
    assert_eq!(Header::parse(&bad), Err(Bad::Header));
    let mut bad = p.clone();
    bad[8] = 1;
    assert_eq!(Header::parse(&bad), Err(Bad::Checksum));
    // A total length past the end of the frame.
    assert_eq!(Header::parse(&p[..0x72]), Err(Bad::Length));
    // A frame with padding after the packet is good.
    let mut long = p.clone();
    long.extend_from_slice(&[0; 10]);
    assert!(Header::parse(&long).is_ok());
}

fn with_frag(frag: u16) -> Vec<u8> {
    let mut h = Header::new([10, 0, 0, 1], [10, 0, 0, 2], ipv4::PROTO_UDP, 8);
    h.frag = frag;
    let mut p = h.to_bytes().to_vec();
    p.resize(28, 0);
    p
}

#[test]
fn fragments_are_dropped() {
    assert!(Header::parse(&with_frag(DF)).is_ok());
    assert_eq!(Header::parse(&with_frag(MF)), Err(Bad::Fragment));
    assert_eq!(Header::parse(&with_frag(185)), Err(Bad::Fragment));
}

#[test]
fn udp_header() {
    let h = UdpHeader { src: 1234, dst: 53, len: 12, check: 0 };
    let mut d = h.to_bytes().to_vec();
    d.extend_from_slice(b"abcd");
    assert_eq!(UdpHeader::parse(&d), Some(h));
    assert_eq!(UdpHeader::parse(&d[..11]), None);
    let short = UdpHeader { len: 7, ..h }.to_bytes();
    assert_eq!(UdpHeader::parse(&short), None);
}

const MAC: MacAddr = MacAddr([2, 0, 0, 0, 0, 1]);
const GW: (u32, [u8; 4]) = (2, [10, 0, 2, 2]);

#[test]
fn neighbour_resolves_and_queues() {
    let mut t = neigh::Table::<u32>::new();
    assert_eq!(t.resolve(GW, 0, 1), Resolve::Wait { probe: true });
    assert_eq!(t.resolve(GW, 10, 2), Resolve::Wait { probe: false });
    assert_eq!(t.lookup(GW), None);
    assert_eq!(t.update(GW, MAC, 20, false), vec![1, 2]);
    assert_eq!(t.lookup(GW), Some(MAC));
    assert_eq!(t.resolve(GW, 30, 3), Resolve::Send { packet: 3, mac: MAC, probe: false });
}

#[test]
fn neighbour_retries_and_gives_up() {
    let mut t = neigh::Table::<u32>::new();
    assert_eq!(t.resolve(GW, 0, 1), Resolve::Wait { probe: true });
    assert!(t.tick(500).is_empty());
    assert_eq!(t.tick(1000), vec![GW]);
    assert_eq!(t.tick(2000), vec![GW]);
    assert!(t.pending());
    // Three requests and no reply: the entry and its packet go away.
    assert!(t.tick(3000).is_empty());
    assert!(t.is_empty());
    assert_eq!(t.dropped, 1);
}

#[test]
fn neighbour_queue_is_bounded() {
    let mut t = neigh::Table::<usize>::new();
    for i in 0..neigh::QUEUE_LEN + 2 {
        t.resolve(GW, 0, i);
    }
    assert_eq!(t.dropped, 2);
    let sent = t.update(GW, MAC, 1, false);
    assert_eq!(sent.len(), neigh::QUEUE_LEN);
    assert_eq!(sent[0], 2);
}

#[test]
fn neighbour_times_out() {
    let mut t = neigh::Table::<u32>::new();
    // A request from the host makes an entry. An unsolicited reply from another host does not.
    assert!(t.update(GW, MAC, 0, true).is_empty());
    assert!(t.update((2, [10, 0, 2, 9]), MAC, 0, false).is_empty());
    assert_eq!(t.len(), 1);
    // After `REACHABLE_MS`, the address is still good, but the table asks again.
    let at = neigh::REACHABLE_MS;
    assert_eq!(t.resolve(GW, at, 7), Resolve::Send { packet: 7, mac: MAC, probe: true });
    assert_eq!(t.resolve(GW, at + 1, 8), Resolve::Send { packet: 8, mac: MAC, probe: false });
    // An entry that nobody uses goes away.
    t.tick(at + 1 + neigh::GC_MS);
    assert!(t.is_empty());
}

#[test]
fn ports_ephemeral_and_conflicts() {
    let mut p = Ports::new(EPHEMERAL);
    let any = |id, reuse| Binding { addr: ipv4::ANY, reuse, id };
    let a = p.bind(0, any(1, false)).unwrap();
    let b = p.bind(0, any(2, false)).unwrap();
    assert!(EPHEMERAL.contains(&a) && EPHEMERAL.contains(&b));
    assert_ne!(a, b);
    assert_eq!(p.bind(5000, any(3, false)), Ok(5000));
    assert_eq!(p.bind(5000, any(4, false)), Err(Errno::EADDRINUSE));
    // A specific address overlaps 0.0.0.0.
    let lo = Binding { addr: ipv4::LOOPBACK, reuse: false, id: 5 };
    assert_eq!(p.bind(5000, lo), Err(Errno::EADDRINUSE));
    // Two different specific addresses do not overlap.
    assert_eq!(p.bind(6000, lo), Ok(6000));
    assert_eq!(p.bind(6000, Binding { addr: [10, 0, 2, 15], reuse: false, id: 6 }), Ok(6000));
    // `SO_REUSEADDR` on both sockets shares the port.
    assert_eq!(p.bind(7000, any(7, true)), Ok(7000));
    assert_eq!(p.bind(7000, any(8, true)), Ok(7000));
    assert_eq!(p.bind(7000, any(9, false)), Err(Errno::EADDRINUSE));
    // A closed socket frees its port.
    p.unbind(5000, 3);
    assert_eq!(p.bind(5000, any(4, false)), Ok(5000));
}

#[test]
fn ports_find_prefers_specific() {
    let mut p = Ports::new(EPHEMERAL);
    p.bind(53, Binding { addr: ipv4::ANY, reuse: true, id: 1 }).unwrap();
    p.bind(53, Binding { addr: ipv4::LOOPBACK, reuse: true, id: 2 }).unwrap();
    let ids: Vec<u64> = p.find(53, ipv4::LOOPBACK).iter().map(|b| b.id).collect();
    assert_eq!(ids, vec![2, 1]);
    let ids: Vec<u64> = p.find(53, [10, 0, 2, 15]).iter().map(|b| b.id).collect();
    assert_eq!(ids, vec![1]);
    p.set_addr(53, 1, [10, 0, 2, 15]);
    assert!(p.find(53, [10, 0, 2, 16]).is_empty());
}

#[test]
fn ports_run_out() {
    let mut p = Ports::new(100..=102);
    for id in 0..3 {
        p.bind(0, Binding { addr: ipv4::ANY, reuse: false, id }).unwrap();
    }
    assert_eq!(p.bind(0, Binding { addr: ipv4::ANY, reuse: false, id: 9 }), Err(Errno::EADDRINUSE));
}

fn qemu_table() -> Table {
    let mut t = Table::new();
    t.add_addr(IfAddr { ifindex: 1, addr: ipv4::LOOPBACK, prefix: 8, loopback: true });
    t.add_addr(IfAddr { ifindex: 2, addr: [10, 0, 2, 15], prefix: 24, loopback: false });
    t.add_route(Route { dst: ipv4::ANY, prefix: 0, gateway: Some([10, 0, 2, 2]), ifindex: 2 });
    t
}

#[test]
fn routes() {
    let t = qemu_table();
    let n = t.lookup([10, 0, 2, 3]).unwrap();
    assert_eq!((n.ifindex, n.hop, n.src, n.local), (2, [10, 0, 2, 3], [10, 0, 2, 15], false));
    let n = t.lookup([8, 8, 8, 8]).unwrap();
    assert_eq!((n.ifindex, n.hop, n.src), (2, [10, 0, 2, 2], [10, 0, 2, 15]));
    // A local address goes to the loopback device.
    let n = t.lookup([10, 0, 2, 15]).unwrap();
    assert_eq!((n.ifindex, n.local), (1, true));
    let n = t.lookup([127, 1, 2, 3]).unwrap();
    assert_eq!((n.ifindex, n.src), (1, [127, 1, 2, 3]));
    assert!(t.lookup([10, 0, 2, 255]).unwrap().broadcast);
    assert!(t.is_broadcast(ipv4::BROADCAST));
    assert!(!t.is_local([10, 0, 2, 16]));
    // Without the default route, a far address has no route.
    let mut t = Table::new();
    t.add_addr(IfAddr { ifindex: 2, addr: [10, 0, 2, 15], prefix: 24, loopback: false });
    assert!(t.lookup([8, 8, 8, 8]).is_none());
}

#[test]
fn ip_parameter() {
    let c = config::parse("10.0.2.15::10.0.2.2:255.255.255.0").unwrap();
    assert_eq!(
        c,
        IpConfig {
            addr: [10, 0, 2, 15],
            prefix: 24,
            gateway: Some([10, 0, 2, 2]),
            device: None,
            hostname: None
        }
    );
    let c = config::parse("192.168.1.5:192.168.1.1:::box:eth1:off").unwrap();
    assert_eq!(c.prefix, 24);
    assert_eq!(c.gateway, None);
    assert_eq!(c.device, Some(String::from("eth1")));
    assert_eq!(c.hostname, Some(String::from("box")));
    assert_eq!(config::parse("10.1.2.3").unwrap().prefix, 8);
    assert_eq!(config::parse("dhcp"), Err(config::Error::Auto));
    assert_eq!(config::parse("10.0.2.15:::::eth0:dhcp"), Err(config::Error::Auto));
    assert_eq!(config::parse("off"), Err(config::Error::Off));
    assert_eq!(config::parse("10.0.2"), Err(config::Error::Invalid));
    assert_eq!(config::parse("10.0.2.15:::255.0.255.0"), Err(config::Error::Invalid));
    assert_eq!(config::mask_to_prefix([255, 255, 255, 255]), Some(32));
    assert_eq!(config::mask_to_prefix([0, 0, 0, 0]), Some(0));
}

#[test]
fn sockaddr_in() {
    let a = sockaddr::make([127, 0, 0, 1], 53);
    assert_eq!(a.len(), 16);
    assert_eq!(&a[2..8], &[0, 53, 127, 0, 0, 1]);
    assert_eq!(sockaddr::parse_bind(&a), Ok(([127, 0, 0, 1], 53)));
    assert_eq!(sockaddr::parse_bind(&a[..15]), Err(Errno::EINVAL));
    let mut unspec = a.clone();
    unspec[0..2].fill(0);
    assert_eq!(sockaddr::parse_bind(&unspec), Err(Errno::EAFNOSUPPORT));
    assert_eq!(sockaddr::parse_connect(&unspec[..2]), Ok(None));
    assert_eq!(sockaddr::parse_send(&unspec), Ok(Some(([127, 0, 0, 1], 53))));
    let mut six = a.clone();
    six[0..2].copy_from_slice(&10u16.to_ne_bytes());
    assert_eq!(sockaddr::parse_connect(&six), Err(Errno::EAFNOSUPPORT));
}

#[test]
fn socket_kinds() {
    assert_eq!(classify(SOCK_DGRAM, 0), Ok(Proto::Udp));
    assert_eq!(classify(SOCK_DGRAM, IPPROTO_UDP), Ok(Proto::Udp));
    assert_eq!(classify(SOCK_DGRAM, IPPROTO_ICMP), Ok(Proto::Ping));
    assert_eq!(classify(SOCK_RAW, IPPROTO_ICMP), Ok(Proto::Raw(1)));
    assert_eq!(classify(SOCK_RAW, 0), Err(Errno::EPROTONOSUPPORT));
    assert_eq!(classify(SOCK_DGRAM, 6), Err(Errno::EPROTONOSUPPORT));
    assert_eq!(classify(SOCK_STREAM, 0), Ok(Proto::Tcp));
    assert_eq!(classify(SOCK_STREAM, 6), Ok(Proto::Tcp));
    assert_eq!(classify(SOCK_STREAM, IPPROTO_UDP), Err(Errno::EPROTONOSUPPORT));
    assert_eq!(classify(SOCK_SEQPACKET, 0), Err(Errno::ESOCKTNOSUPPORT));
    assert_eq!(classify(SOCK_DGRAM, 1000), Err(Errno::EINVAL));
}

fn send(s: &Dgram, to: Option<([u8; 4], u16)>, data: &[u8]) -> Result<usize, Errno> {
    let msg = Message {
        data: data.to_vec(),
        addr: to.map(|(a, p)| sockaddr::make(a, p)),
        ..Message::default()
    };
    s.send(&NoPaths, msg, 0, true)
}

/// The sockets over the loopback device. The tables are global, so one test does all of it.
#[test]
fn loopback_sockets() {
    rk_net::dev::init();
    crate::init();
    let lo = ipv4::LOOPBACK;

    // UDP: a datagram goes from one socket to the other, with the address of the sender.
    let a = Dgram::new(Proto::Udp);
    let b = Dgram::new(Proto::Udp);
    a.bind(&NoPaths, &sockaddr::make(lo, 0)).unwrap();
    let port = sockaddr::parse_bind(&a.name()).unwrap().1;
    assert!(crate::ports::EPHEMERAL.contains(&port));
    assert_eq!(b.bind(&NoPaths, &sockaddr::make(lo, port)), Err(Errno::EADDRINUSE));
    assert_eq!(b.bind(&NoPaths, &sockaddr::make([10, 9, 9, 9], 0)), Err(Errno::EADDRNOTAVAIL));
    assert_eq!(send(&b, None, b"x"), Err(Errno::EDESTADDRREQ));
    assert_eq!(send(&b, Some((lo, port)), b"hello"), Ok(5));
    assert_ne!(a.poll() & rk_abi::native::poll::POLLIN, 0);
    assert_eq!(a.readable(), Ok(5));
    let r = a.recv(4, MSG_PEEK, true).unwrap();
    assert_eq!((r.data.as_slice(), r.len, r.flags), (&b"hell"[..], 5, MSG_TRUNC));
    let r = a.recv(100, 0, true).unwrap();
    assert_eq!(r.data, b"hello");
    let bport = sockaddr::parse_bind(&b.name()).unwrap().1;
    assert_eq!(r.addr, Some(sockaddr::make(lo, bport)));
    assert_eq!(a.recv(100, 0, true).err(), Some(Errno::EAGAIN));

    // A connected socket takes only the datagrams of its peer.
    a.connect(&NoPaths, &sockaddr::make(lo, bport), true).unwrap();
    assert_eq!(a.peer_name(), Ok(sockaddr::make(lo, bport)));
    let c = Dgram::new(Proto::Udp);
    send(&c, Some((lo, port)), b"other").unwrap();
    assert_eq!(a.recv(100, 0, true).err(), Some(Errno::EAGAIN));
    send(&a, None, b"reply").unwrap();
    assert_eq!(b.recv(100, 0, true).unwrap().data, b"reply");

    // A datagram to a port without a socket gives an ICMP error, and the connected socket gets
    // `ECONNREFUSED`.
    let d = Dgram::new(Proto::Udp);
    d.connect(&NoPaths, &sockaddr::make(lo, 9), true).unwrap();
    assert_eq!(send(&d, None, b"lost"), Ok(4));
    assert_eq!(d.recv(100, 0, true).err(), Some(Errno::ECONNREFUSED));
    assert_eq!(d.recv(100, 0, true).err(), Some(Errno::EAGAIN));

    // A closed socket frees its port.
    a.release();
    let e = Dgram::new(Proto::Udp);
    assert!(e.bind(&NoPaths, &sockaddr::make(lo, port)).is_ok());

    // No route: `ENETUNREACH`.
    assert_eq!(send(&e, Some(([8, 8, 8, 8], 53)), b"q"), Err(Errno::ENETUNREACH));

    // An ICMP echo socket: the stack answers the request, and the reply has the identifier of
    // the socket.
    let p = Dgram::new(Proto::Ping);
    let req = [ICMP_ECHO, 0, 0, 0, 0, 0, 0, 1, b'p', b'i', b'n', b'g'];
    assert_eq!(send(&p, Some((lo, 0)), &req), Ok(12));
    let r = p.recv(100, 0, true).unwrap();
    let id = sockaddr::parse_bind(&p.name()).unwrap().1;
    assert_eq!(r.data[0], ICMP_ECHOREPLY);
    assert_eq!(u16::from_be_bytes([r.data[4], r.data[5]]), id);
    assert_eq!(&r.data[6..], &[0, 1, b'p', b'i', b'n', b'g']);
    assert_eq!(checksum::checksum(&r.data), 0);
    assert_eq!(send(&p, Some((lo, 0)), &[0; 4]), Err(Errno::EINVAL));

    // A raw ICMP socket sees the request and the reply, with the IPv4 header.
    let raw = Dgram::new(Proto::Raw(1));
    send(&p, Some((lo, 0)), &req).unwrap();
    let r = raw.recv(200, 0, true).unwrap();
    let h = Header::parse(&r.data).unwrap();
    assert_eq!((h.protocol, r.data[h.hlen]), (1, ICMP_ECHO));
    let r = raw.recv(200, 0, true).unwrap();
    assert_eq!(r.data[20], ICMP_ECHOREPLY);
    assert!(p.recv(100, 0, true).is_ok());

    tcp_loopback();
}

fn tcp_send(s: &crate::Stream, data: &[u8]) -> Result<usize, Errno> {
    s.send(&NoPaths, Message { data: data.to_vec(), ..Message::default() }, 0, true)
}

/// Reads until `n` bytes came or nothing more comes.
fn tcp_read(s: &crate::Stream, n: usize) -> Vec<u8> {
    let mut got = Vec::new();
    while got.len() < n {
        match s.recv(n - got.len(), 0, true) {
            Ok(r) if !r.data.is_empty() => got.extend_from_slice(&r.data),
            _ => break,
        }
    }
    got
}

/// TCP over the loopback device. The `loopback_sockets` test calls this, because the tables are
/// global. The host has no clock, so the timers do not run.
fn tcp_loopback() {
    use crate::Stream;
    use rk_abi::native::poll::{POLLHUP, POLLIN, POLLOUT, POLLRDHUP};
    use rk_abi::native::socket::{SO_ERROR, SO_LINGER, SO_REUSEADDR, SOL_SOCKET};
    use rk_net::consts::{MSG_WAITALL, SHUT_WR};
    let lo = ipv4::LOOPBACK;
    let int = |v: i32| v.to_ne_bytes().to_vec();

    let l = Stream::new();
    l.bind(&NoPaths, &sockaddr::make(lo, 0)).unwrap();
    let port = sockaddr::parse_bind(&l.name()).unwrap().1;
    l.listen(4).unwrap();
    assert_eq!(l.get_option(SOL_SOCKET, rk_abi::native::socket::SO_ACCEPTCONN), Ok(int(1)));
    // A listening socket keeps its port, also from a socket with `SO_REUSEADDR`.
    let other = Stream::new();
    other.set_option(SOL_SOCKET, SO_REUSEADDR, &int(1)).unwrap();
    assert_eq!(other.bind(&NoPaths, &sockaddr::make(lo, port)), Err(Errno::EADDRINUSE));
    assert_eq!(l.accept(true).err(), Some(Errno::EAGAIN));

    // A new socket is writable and hung up, as Linux.
    let c = Stream::new();
    assert_eq!(c.poll() & (POLLOUT | POLLHUP | POLLIN), POLLOUT | POLLHUP);
    assert_eq!(c.recv(10, 0, true).err(), Some(Errno::ENOTCONN));
    assert_eq!(tcp_send(&c, b"x"), Err(Errno::EPIPE));
    assert_eq!(c.connect(&NoPaths, &sockaddr::make(lo, port), true), Err(Errno::EINPROGRESS));
    assert_eq!(c.get_option(SOL_SOCKET, SO_ERROR), Ok(int(0)));
    assert_eq!(c.connect(&NoPaths, &sockaddr::make(lo, port), true), Ok(()));
    assert_eq!(c.connect(&NoPaths, &sockaddr::make(lo, port), true), Err(Errno::EISCONN));
    assert_ne!(l.poll() & POLLIN, 0);
    let a = l.accept(true).unwrap();
    let a = a.as_any().downcast_ref::<Stream>().unwrap();
    assert_eq!(a.peer_name(), Ok(c.name()));
    assert_eq!(c.peer_name(), Ok(a.name()));
    assert_eq!(c.poll() & (POLLOUT | POLLHUP | POLLIN), POLLOUT);

    // Bulk data with a check of each byte.
    let data: Vec<u8> = (0..100_000u32).map(|i| (i * 7 + i / 251) as u8).collect();
    assert_eq!(tcp_send(&c, &data), Ok(data.len()));
    assert_eq!(tcp_read(a, data.len()), data);
    assert_eq!(a.recv(10, 0, true).err(), Some(Errno::EAGAIN));

    // `MSG_PEEK` leaves the data, and `MSG_WAITALL` without a wait gives what is there.
    tcp_send(a, b"12345").unwrap();
    assert_eq!(c.recv(3, MSG_PEEK, true).unwrap().data, b"123");
    assert_eq!(c.readable(), Ok(5));
    assert_eq!(c.recv(10, MSG_WAITALL, true).unwrap().data, b"12345");

    // A half close: the peer reads the end, and it can still send.
    c.shutdown(SHUT_WR).unwrap();
    assert_eq!(tcp_send(&c, b"x"), Err(Errno::EPIPE));
    assert_eq!(a.recv(10, 0, true).unwrap().data, b"");
    assert_ne!(a.poll() & POLLRDHUP, 0);
    tcp_send(a, b"bye").unwrap();
    assert_eq!(c.recv(10, 0, true).unwrap().data, b"bye");
    a.release();
    assert_eq!(c.recv(10, 0, true).unwrap().data, b"");
    assert_ne!(c.poll() & POLLHUP, 0);
    c.release();

    // No listener: an RST, and `ECONNREFUSED`.
    let d = Stream::new();
    assert_eq!(d.connect(&NoPaths, &sockaddr::make(lo, 9), true), Err(Errno::EINPROGRESS));
    assert_eq!(d.connect(&NoPaths, &sockaddr::make(lo, 9), true), Err(Errno::ECONNREFUSED));
    d.release();

    // A close with data that the program did not read sends an RST.
    let e = Stream::new();
    let _ = e.connect(&NoPaths, &sockaddr::make(lo, port), true);
    let f = l.accept(true).unwrap();
    tcp_send(&e, b"unread").unwrap();
    f.release();
    assert_eq!(e.recv(10, 0, true).err(), Some(Errno::ECONNRESET));
    assert_eq!(e.recv(10, 0, true).unwrap().data, b"");
    assert_eq!(tcp_send(&e, b"x"), Err(Errno::EPIPE));
    e.release();

    // `SO_LINGER` with 0 also sends an RST.
    let g = Stream::new();
    let _ = g.connect(&NoPaths, &sockaddr::make(lo, port), true);
    let h = l.accept(true).unwrap();
    let mut linger = int(1);
    linger.extend_from_slice(&int(0));
    g.set_option(SOL_SOCKET, SO_LINGER, &linger).unwrap();
    g.release();
    assert_eq!(h.recv(10, 0, true).err(), Some(Errno::ECONNRESET));
    h.release();

    // A closed listener frees its port.
    l.release();
    let m = Stream::new();
    m.set_option(SOL_SOCKET, SO_REUSEADDR, &int(1)).unwrap();
    assert_eq!(m.bind(&NoPaths, &sockaddr::make(lo, port)), Ok(()));
    m.release();
}
