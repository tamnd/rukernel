use crate::config::{self, IpConfig};
use crate::ip::{self, Ip};
use crate::ipv4::Addr;
use crate::ipv4::{self, Bad, DF, Header, MF, UdpHeader};
use crate::neigh::{self, Resolve};
use crate::ports::{Binding, EPHEMERAL, Ports};
use crate::route::{IfAddr, Link, Match, Route, Table};
use crate::{Dgram, Proto, checksum, classify, sockaddr};
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_abi::native::inet::{IPPROTO_ICMP, IPPROTO_UDP};
use rk_abi::native::netlink::{NLM_F_CREATE, NLM_F_EXCL, NLM_F_REPLACE};
use rk_abi::native::rtnetlink::{
    RT_SCOPE_HOST, RT_SCOPE_LINK, RT_SCOPE_UNIVERSE, RT_TABLE_LOCAL, RT_TABLE_MAIN, RTN_BROADCAST,
    RTN_LOCAL, RTN_UNICAST, RTPROT_KERNEL,
};
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
fn fragments_are_valid_headers() {
    assert!(Header::parse(&with_frag(DF)).is_ok());
    assert!(!Header::parse(&with_frag(DF)).unwrap().is_fragment());
    assert!(Header::parse(&with_frag(MF)).unwrap().is_fragment());
    let h = Header::parse(&with_frag(185)).unwrap();
    assert!(h.is_fragment());
    assert_eq!(h.frag_offset(), 185 * 8);
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
    let any = |id, reuse| Binding::v4(ipv4::ANY, reuse, id);
    let a = p.bind(0, any(1, false)).unwrap();
    let b = p.bind(0, any(2, false)).unwrap();
    assert!(EPHEMERAL.contains(&a) && EPHEMERAL.contains(&b));
    assert_ne!(a, b);
    assert_eq!(p.bind(5000, any(3, false)), Ok(5000));
    assert_eq!(p.bind(5000, any(4, false)), Err(Errno::EADDRINUSE));
    // A specific address overlaps 0.0.0.0.
    let lo = Binding::v4(ipv4::LOOPBACK, false, 5);
    assert_eq!(p.bind(5000, lo), Err(Errno::EADDRINUSE));
    // Two different specific addresses do not overlap.
    assert_eq!(p.bind(6000, lo), Ok(6000));
    assert_eq!(p.bind(6000, Binding::v4([10, 0, 2, 15], false, 6)), Ok(6000));
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
    p.bind(53, Binding::v4(ipv4::ANY, true, 1)).unwrap();
    p.bind(53, Binding::v4(ipv4::LOOPBACK, true, 2)).unwrap();
    let ids: Vec<u64> = p.find(53, ip::mapped(ipv4::LOOPBACK)).iter().map(|b| b.id).collect();
    assert_eq!(ids, vec![2, 1]);
    let ids: Vec<u64> = p.find(53, ip::mapped([10, 0, 2, 15])).iter().map(|b| b.id).collect();
    assert_eq!(ids, vec![1]);
    p.set_addr(53, 1, ip::mapped([10, 0, 2, 15]));
    assert!(p.find(53, ip::mapped([10, 0, 2, 16])).is_empty());
}

#[test]
fn ports_run_out() {
    let mut p = Ports::new(100..=102);
    for id in 0..3 {
        p.bind(0, Binding::v4(ipv4::ANY, false, id)).unwrap();
    }
    assert_eq!(p.bind(0, Binding::v4(ipv4::ANY, false, 9)), Err(Errno::EADDRINUSE));
}

const LO: Link = Link { ifindex: 1, up: true, loopback: true };
const ETH: Link = Link { ifindex: 2, up: true, loopback: false };

fn qemu_table() -> Table {
    let mut t = Table::new();
    t.set_loopback(1);
    let mut lo = IfAddr::new(1, ipv4::LOOPBACK, 8, "lo");
    lo.scope = RT_SCOPE_HOST as u8;
    t.insert_addr(lo).unwrap();
    t.sync_link(LO);
    let mut eth = IfAddr::new(2, [10, 0, 2, 15], 24, "eth0");
    eth.broadcast = eth.default_broadcast();
    t.insert_addr(eth).unwrap();
    t.sync_link(ETH);
    let gw = Route::new(ipv4::ANY, 0, Some([10, 0, 2, 2]), 2);
    t.insert_route(gw, NLM_F_CREATE).unwrap();
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
    assert_eq!((n.ifindex, n.src, n.local), (1, ipv4::LOOPBACK, true));
    assert!(t.lookup([10, 0, 2, 255]).unwrap().broadcast);
    assert!(t.is_broadcast(ipv4::BROADCAST));
    assert!(!t.is_local([10, 0, 2, 16]));
    // Without the default route, a far address has no route.
    let mut t = Table::new();
    t.insert_addr(IfAddr::new(2, [10, 0, 2, 15], 24, "eth0")).unwrap();
    t.sync_link(ETH);
    assert_eq!(t.lookup([8, 8, 8, 8]), Err(Errno::ENETUNREACH));
}

/// The routes of the kernel for the addresses, in the order of `ip route show table all`.
#[test]
fn kernel_routes() {
    let t = qemu_table();
    let got: Vec<(u32, Addr, u8, u8, u8)> =
        t.routes().iter().map(|r| (r.table, r.dst, r.prefix, r.kind, r.scope)).collect();
    let (main, local) = (RT_TABLE_MAIN, RT_TABLE_LOCAL);
    let (uni, loc, bc) = (RTN_UNICAST as u8, RTN_LOCAL as u8, RTN_BROADCAST as u8);
    let (univ, link, host) = (RT_SCOPE_UNIVERSE as u8, RT_SCOPE_LINK as u8, RT_SCOPE_HOST as u8);
    assert_eq!(
        got,
        vec![
            (main, [0, 0, 0, 0], 0, uni, univ),
            (main, [10, 0, 2, 0], 24, uni, link),
            (local, [10, 0, 2, 15], 32, loc, host),
            (local, [10, 0, 2, 255], 32, bc, link),
            (local, [127, 0, 0, 0], 8, loc, host),
            (local, [127, 0, 0, 1], 32, loc, host),
            (local, [127, 255, 255, 255], 32, bc, link),
        ]
    );
    let r = &t.routes()[1];
    assert_eq!((r.protocol, r.prefsrc, r.ifindex), (RTPROT_KERNEL as u8, Some([10, 0, 2, 15]), 2));
}

#[test]
fn addresses_and_link_state() {
    let mut t = qemu_table();
    // A second address in the subnet is secondary and adds only its local route.
    t.insert_addr(IfAddr::new(2, [10, 0, 2, 16], 24, "eth0")).unwrap();
    let c = t.sync_link(ETH);
    assert_eq!(c.added.len(), 1);
    assert_eq!(c.added[0].prefsrc, Some([10, 0, 2, 15]));
    assert!(t.addrs_of(2).nth(1).unwrap().is_secondary());
    assert_eq!(t.insert_addr(IfAddr::new(2, [10, 0, 2, 16], 24, "eth0")), Err(Errno::EEXIST));
    // A link that goes down keeps only its local routes.
    t.link_down(2);
    assert!(t.routes().iter().filter(|r| r.ifindex == 2).all(|r| r.scope == RT_SCOPE_HOST as u8));
    assert_eq!(t.lookup([8, 8, 8, 8]), Err(Errno::ENETUNREACH));
    // The removal of the primary address takes the secondary address and all routes with it.
    let removed = t.remove_addr(t.addrs().iter().position(|a| a.local == [10, 0, 2, 15]).unwrap());
    assert_eq!(removed.len(), 2);
    assert_eq!(removed[1].local, [10, 0, 2, 15]);
    t.sync_link(Link { up: false, ..ETH });
    assert!(t.routes().iter().all(|r| r.ifindex != 2));
}

#[test]
fn insert_and_delete_routes() {
    let mut t = qemu_table();
    let r = Route::new([192, 168, 0, 0], 16, Some([10, 0, 2, 3]), 2);
    assert_eq!(
        t.insert_route(r.clone(), NLM_F_CREATE | NLM_F_EXCL),
        Ok(Some(NLM_F_CREATE | NLM_F_EXCL))
    );
    assert_eq!(t.insert_route(r.clone(), NLM_F_CREATE | NLM_F_EXCL), Err(Errno::EEXIST));
    assert_eq!(t.insert_route(r.clone(), NLM_F_CREATE), Err(Errno::EEXIST));
    assert_eq!(t.insert_route(r.clone(), NLM_F_REPLACE), Ok(None));
    let other = Route { gateway: Some([10, 0, 2, 4]), ..r.clone() };
    assert_eq!(t.insert_route(other.clone(), 0), Err(Errno::ENOENT));
    assert_eq!(t.insert_route(other.clone(), NLM_F_REPLACE), Ok(Some(NLM_F_REPLACE)));
    assert_eq!(t.lookup([192, 168, 1, 1]).unwrap().hop, [10, 0, 2, 4]);
    let mut m = Match {
        table: RT_TABLE_MAIN,
        dst: [192, 168, 0, 0],
        prefix: 16,
        gateway: Some([10, 0, 2, 3]),
        ..Match::default()
    };
    assert_eq!(t.delete_route(&m), Err(Errno::ESRCH));
    m.gateway = None;
    assert_eq!(t.delete_route(&m).unwrap(), other);
    m.table = 100;
    assert_eq!(t.delete_route(&m), Err(Errno::ESRCH));
    // A gateway must be on a link, and a route of the scope `host` has no gateway.
    let up = |i: u32| (i <= 2).then_some(true);
    let far = Route::new(ipv4::ANY, 0, Some([192, 0, 2, 1]), 0);
    assert_eq!(t.check_nexthop(&far, up), Err(Errno::ENETUNREACH));
    let near = Route::new(ipv4::ANY, 0, Some([10, 0, 2, 9]), 0);
    assert_eq!(t.check_nexthop(&near, up), Ok(2));
    let host = Route { scope: RT_SCOPE_HOST as u8, ..near };
    assert_eq!(t.check_nexthop(&host, up), Err(Errno::EINVAL));
    assert_eq!(t.check_nexthop(&Route::new([1, 0, 0, 0], 8, None, 7), up), Err(Errno::ENODEV));
}

#[test]
fn neighbour_entries() {
    let mut n: neigh::Table<u32> = neigh::Table::new();
    let _ = n.resolve((2, [10, 0, 2, 2]), 0, 1);
    n.update((2, [10, 0, 2, 3]), MacAddr([2, 0, 0, 0, 0, 1]), 0, true);
    let e = n.entries(neigh::REACHABLE_MS + 5);
    assert_eq!(e.len(), 2);
    assert_eq!((e[0].state, e[0].mac, e[0].probes), (neigh::Nud::Incomplete, None, 1));
    assert_eq!(e[1].state, neigh::Nud::Stale);
    assert_eq!(e[1].confirmed, neigh::REACHABLE_MS + 5);
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
    ipv6_loopback();
    ipv6_groups();
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

/// An IPv6 address from its eight groups.
fn v6(g: [u16; 8]) -> Ip {
    let mut a = [0; 16];
    for (i, w) in g.iter().enumerate() {
        a[2 * i..2 * i + 2].copy_from_slice(&w.to_be_bytes());
    }
    a
}

#[test]
fn mapped_addresses() {
    let m = ip::mapped([10, 0, 2, 15]);
    assert_eq!(ip::v4(&m), Some([10, 0, 2, 15]));
    assert_eq!(ip::v4(&ip::LOOPBACK), None);
    assert!(ip::is_any(&ip::ANY) && ip::is_any(&ip::V4_ANY));
    // `::` takes IPv4 only without `IPV6_V6ONLY`.
    assert!(ip::takes(&ip::ANY, false, &m));
    assert!(!ip::takes(&ip::ANY, true, &m));
    assert!(ip::takes(&ip::ANY, true, &ip::LOOPBACK));
    assert!(!ip::takes(&ip::V4_ANY, false, &ip::LOOPBACK));
    assert!(ip::overlap(&ip::ANY, false, &ip::V4_ANY, false));
    assert!(!ip::overlap(&ip::ANY, true, &ip::V4_ANY, false));
}

#[test]
fn ports_dual_stack() {
    let mut p = Ports::new(EPHEMERAL);
    let six = |addr, id, v6only| Binding { addr, reuse: false, id, v6only };
    p.bind(80, six(ip::ANY, 1, false)).unwrap();
    // A dual stack socket on `::` has the port for IPv4 too.
    assert_eq!(p.bind(80, Binding::v4(ipv4::ANY, false, 2)), Err(Errno::EADDRINUSE));
    p.bind(81, six(ip::ANY, 3, true)).unwrap();
    assert_eq!(p.bind(81, Binding::v4(ipv4::ANY, false, 4)), Ok(81));
    assert_eq!(p.bind(81, six(ip::LOOPBACK, 5, true)), Err(Errno::EADDRINUSE));
    let ids: Vec<u64> = p.find(81, ip::mapped(ipv4::LOOPBACK)).iter().map(|b| b.id).collect();
    assert_eq!(ids, vec![4]);
    let ids: Vec<u64> = p.find(81, ip::LOOPBACK).iter().map(|b| b.id).collect();
    assert_eq!(ids, vec![3]);
}

#[test]
fn ipv6_checksum_and_header() {
    let (src, dst) = (ip::LOOPBACK, ip::LOOPBACK);
    let mut udp = vec![0x12, 0x34, 0, 53, 0, 10, 0, 0, b'h', b'i'];
    let sum = checksum::upper(&src, &dst, 17, &udp);
    udp[6..8].copy_from_slice(&sum.to_be_bytes());
    assert_eq!(checksum::upper(&src, &dst, 17, &udp), 0);
    // Two IPv4-mapped addresses use the pseudo header of IPv4.
    let (a, b) = ([127, 0, 0, 1], [127, 0, 0, 1]);
    assert_eq!(
        checksum::upper(&ip::mapped(a), &ip::mapped(b), 17, &udp[..8]),
        checksum::fold(checksum::add(checksum::pseudo(a, b, 17, 8), &udp[..8]))
    );
    let h = crate::ipv6::Header::new(v6([0xfe80, 0, 0, 0, 0, 0, 0, 1]), ip::LOOPBACK, 58, 8);
    let mut pkt = h.to_bytes().to_vec();
    pkt.extend_from_slice(&[128, 0, 0, 0, 0, 1, 0, 1]);
    let r = crate::ipv6::Header::parse(&pkt).unwrap();
    assert_eq!((r.src, r.dst, r.protocol, r.l4), (h.src, h.dst, 58, 40));
    assert_eq!(crate::ipv6::Header::parse(&pkt[..44]), Err(crate::ipv6::Bad::Length));
}

#[test]
fn ipv6_addresses_and_routes() {
    use crate::route6::{Addr6, Route6, Table6};
    let mut t = Table6::new();
    t.set_loopback(1);
    t.insert_addr(Addr6::new(1, ip::LOOPBACK, 128)).unwrap();
    let mac = MacAddr([0x52, 0x54, 0, 0x12, 0x34, 0x56]);
    let ll = crate::ipv6::link_local(crate::ipv6::eui64(mac));
    assert_eq!(ll, v6([0xfe80, 0, 0, 0, 0x5054, 0xff, 0xfe12, 0x3456]));
    t.insert_addr(Addr6::new(2, ll, 64)).unwrap();
    let site = v6([0xfec0, 0, 0, 0, 0, 0, 0, 0x0f]);
    t.insert_addr(Addr6::new(2, site, 64)).unwrap();
    assert_eq!(t.insert_addr(Addr6::new(2, site, 64)).err(), Some(Errno::EEXIST));
    // A local address goes on the loopback device.
    let n = t.lookup(&site, 0).unwrap();
    assert_eq!((n.ifindex, n.local), (1, true));
    // The prefix route reaches the link, with the address of the same scope as the source.
    let peer = v6([0xfec0, 0, 0, 0, 0, 0, 0, 2]);
    let n = t.lookup(&peer, 0).unwrap();
    assert_eq!((n.ifindex, n.hop, n.src), (2, peer, site));
    let n = t.lookup(&v6([0xfe80, 0, 0, 0, 0, 0, 0, 2]), 2).unwrap();
    assert_eq!(n.src, ll);
    assert_eq!(t.lookup(&v6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1]), 0).err(), Some(Errno::ENETUNREACH));
    // A default route through a router.
    let gw = v6([0xfe80, 0, 0, 0, 0, 0, 0, 2]);
    t.insert_route(Route6::new(ip::ANY, 0, Some(gw), 2), NLM_F_CREATE).unwrap();
    let n = t.lookup(&v6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1]), 0).unwrap();
    assert_eq!((n.ifindex, n.hop), (2, gw));
    let (gone, _) = t.link_down(2);
    assert_eq!(gone.len(), 2);
    assert!(t.lookup(&peer, 0).is_err());
}

#[test]
fn sockaddr_in6() {
    use rk_net::consts::{AF_INET, AF_INET6};
    let a = sockaddr::make_in(AF_INET6, &ip::LOOPBACK, 53, 0);
    assert_eq!(a.len(), sockaddr::LEN6);
    assert_eq!(sockaddr::parse_bind_in(AF_INET6, &a), Ok((ip::LOOPBACK, 53, 0)));
    assert_eq!(sockaddr::parse_connect_in(AF_INET6, &a[..20]), Err(Errno::EINVAL));
    assert_eq!(sockaddr::parse_send_in(AF_INET6, &a[..24]), Ok(Some((ip::LOOPBACK, 53, 0))));
    let mut ll = a.clone();
    ll[8..24].copy_from_slice(&v6([0xfe80, 0, 0, 0, 0, 0, 0, 2]));
    ll[24..28].copy_from_slice(&2u32.to_ne_bytes());
    assert_eq!(sockaddr::parse_bind_in(AF_INET6, &ll).map(|a| a.2), Ok(2));
    // An IPv4 socket gives a `sockaddr_in` with the IPv4 address of a mapped address.
    let four = sockaddr::make_in(AF_INET, &ip::mapped([127, 0, 0, 1]), 53, 0);
    assert_eq!(four, sockaddr::make([127, 0, 0, 1], 53));
}

/// A segment routing header with the segments `segs` and `left` segments left.
fn srh(segs: &[Ip], left: u8) -> Vec<u8> {
    let n = segs.len() as u8;
    let mut h = vec![0, 2 * n, 4, left, n - 1, 0, 0, 0];
    for s in segs {
        h.extend_from_slice(s);
    }
    h
}

#[test]
fn routing_header_on_send() {
    use crate::socket::push_rthdr;
    let (a, b, c, d) =
        (v6([1, 0, 0, 0, 0, 0, 0, 1]), v6([2, 0, 0, 0, 0, 0, 0, 2]), v6([3; 8]), v6([4; 8]));
    // Segment routing: segment 0 is the final destination, and the packet goes to the segment
    // "segments left", as `ipv6_push_rthdr4`.
    let (h, first) = push_rthdr(&srh(&[a, b, c], 2), &d, 17);
    assert_eq!(first, c);
    assert_eq!(&h[..8], &[17, 6, 4, 2, 2, 0, 0, 0]);
    assert_eq!((&h[8..24], &h[24..40], &h[40..56]), (&d[..], &b[..], &c[..]));
    // Type 2: the packet goes to the address of the header, and the header has the final
    // destination, as `ipv6_push_rthdr0`.
    let mut t2 = vec![0, 2, 2, 1, 0, 0, 0, 0];
    t2.extend_from_slice(&a);
    let (h, first) = push_rthdr(&t2, &d, 58);
    assert_eq!((first, h[0], &h[8..24]), (a, 58, &d[..]));
}

fn send6(s: &Dgram, to: Option<(Ip, u16)>, data: &[u8]) -> Result<usize, Errno> {
    use rk_net::consts::AF_INET6;
    let msg = Message {
        data: data.to_vec(),
        addr: to.map(|(a, p)| sockaddr::make_in(AF_INET6, &a, p, 0)),
        ..Message::default()
    };
    s.send(&NoPaths, msg, 0, true)
}

/// UDP, ICMPv6 echo, raw sockets and TCP of IPv6 over the loopback device. The
/// `loopback_sockets` test calls this, because the tables are global.
fn ipv6_loopback() {
    use crate::{Stream, ipv6};
    use rk_abi::native::in6::{
        IPV6_ADDRFORM, IPV6_HOPLIMIT, IPV6_PKTINFO, IPV6_RECVHOPLIMIT, IPV6_RECVPKTINFO,
        IPV6_RTHDR, IPV6_V6ONLY,
    };
    use rk_abi::native::inet::IPPROTO_IPV6;
    use rk_net::consts::{AF_INET, AF_INET6};
    let lo = ip::LOOPBACK;
    let name = |a: &[u8]| sockaddr::parse_bind_in(AF_INET6, a).unwrap();
    let make = |a: &Ip, p| sockaddr::make_in(AF_INET6, a, p, 0);
    let int = |v: i32| v.to_ne_bytes().to_vec();

    // UDP of IPv6.
    let a = Dgram::new6(Proto::Udp);
    let b = Dgram::new6(Proto::Udp);
    a.bind(&NoPaths, &make(&lo, 0)).unwrap();
    let port = name(&a.name()).1;
    assert_eq!(a.get_option(IPPROTO_IPV6, IPV6_V6ONLY), Ok(int(1)));
    assert_eq!(send6(&b, Some((lo, port)), b"six"), Ok(3));
    let r = a.recv(100, 0, true).unwrap();
    assert_eq!(r.data, b"six");
    assert_eq!(r.addr.map(|a| name(&a)), Some((lo, name(&b.name()).1, 0)));
    assert!(r.control.is_empty());
    // A bound socket keeps `IPV6_V6ONLY`.
    assert_eq!(a.set_option(IPPROTO_IPV6, IPV6_V6ONLY, &int(0)), Err(Errno::EINVAL));
    // The control messages of `IPV6_RECVPKTINFO` and `IPV6_RECVHOPLIMIT`, in the order of Linux.
    a.set_option(IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &int(1)).unwrap();
    a.set_option(IPPROTO_IPV6, IPV6_RECVPKTINFO, &int(1)).unwrap();
    send6(&b, Some((lo, port)), b"cm").unwrap();
    let r = a.recv(100, 0, true).unwrap();
    let mut info = lo.to_vec();
    info.extend_from_slice(&1u32.to_ne_bytes());
    let hops = int(i32::from(ipv6::DEFAULT_HOPS));
    let want = [(IPPROTO_IPV6, IPV6_PKTINFO, info), (IPPROTO_IPV6, IPV6_HOPLIMIT, hops)];
    assert_eq!(r.control, want);

    // A dual stack socket on `::` takes IPv4 datagrams with a mapped source.
    let d = Dgram::new6(Proto::Udp);
    d.bind(&NoPaths, &make(&ip::ANY, 0)).unwrap();
    let dport = name(&d.name()).1;
    let four = Dgram::new(Proto::Udp);
    assert_eq!(send(&four, Some((ipv4::LOOPBACK, dport)), b"v4"), Ok(2));
    let r = d.recv(100, 0, true).unwrap();
    assert_eq!(r.data, b"v4");
    let src = name(&r.addr.unwrap()).0;
    assert_eq!(src, ip::mapped(ipv4::LOOPBACK));
    // It answers to the mapped address with IPv4.
    assert_eq!(send6(&d, Some((src, sockaddr::parse_bind(&four.name()).unwrap().1)), b"re"), Ok(2));
    assert_eq!(four.recv(100, 0, true).unwrap().data, b"re");
    // A socket with `IPV6_V6ONLY` does not reach IPv4.
    let o = Dgram::new6(Proto::Udp);
    o.set_option(IPPROTO_IPV6, IPV6_V6ONLY, &int(1)).unwrap();
    assert_eq!(send6(&o, Some((src, 9)), b"x"), Err(Errno::ENETUNREACH));

    // A socket with `IPV6_RTHDR` sends its datagrams through the routing header, and the
    // checksum is for the final destination. The input drops a segment routing header while
    // `seg6_enabled` is 0, as Linux.
    let r6 = Dgram::new6(Proto::Udp);
    r6.set_option(IPPROTO_IPV6, IPV6_RTHDR, &srh(&[lo, lo, lo], 1)).unwrap();
    assert_eq!(send6(&r6, Some((lo, port)), b"rthdr"), Ok(5));
    assert_eq!(a.recv(100, 0, true).map(|r| r.data), Err(Errno::EAGAIN));
    let seg6 = |v: &[u8]| {
        for d in ["all", "lo"] {
            rk_net::sysctl::write(&alloc::format!("ipv6/conf/{d}/seg6_enabled"), v).unwrap();
        }
    };
    seg6(b"1\n");
    // The input goes to the next segment, an address of the host, with one hop less, and then
    // to the final destination.
    assert_eq!(send6(&r6, Some((lo, port)), b"rthdr"), Ok(5));
    let r = a.recv(100, 0, true).unwrap();
    assert_eq!(r.data, b"rthdr");
    let hops = int(i32::from(ipv6::DEFAULT_HOPS) - 1);
    assert_eq!(r.control.last(), Some(&(IPPROTO_IPV6, IPV6_HOPLIMIT, hops)));
    seg6(b"0\n");

    // `IPV6_ADDRFORM` changes a UDP socket with an IPv4 peer to `AF_INET`.
    let f = Dgram::new6(Proto::Udp);
    let fourport = sockaddr::parse_bind(&four.name()).unwrap().1;
    assert_eq!(f.set_option(IPPROTO_IPV6, IPV6_ADDRFORM, &int(2)), Err(Errno::ENOTCONN));
    assert_eq!(f.set_option(IPPROTO_IPV6, IPV6_ADDRFORM, &int(10)), Err(Errno::EINVAL));
    f.connect(&NoPaths, &make(&lo, fourport), true).unwrap();
    assert_eq!(f.set_option(IPPROTO_IPV6, IPV6_ADDRFORM, &int(2)), Err(Errno::EADDRNOTAVAIL));
    f.connect(&NoPaths, &make(&src, fourport), true).unwrap();
    assert_eq!(f.set_option(IPPROTO_IPV6, IPV6_ADDRFORM, &int(2)), Ok(()));
    assert_eq!(f.family(), AF_INET);
    assert_eq!(f.peer_name(), Ok(sockaddr::make(ipv4::LOOPBACK, fourport)));
    assert_eq!(send(&f, None, b"form"), Ok(4));
    assert_eq!(four.recv(100, 0, true).unwrap().data, b"form");
    let pf = Dgram::new6(Proto::Ping);
    assert_eq!(pf.set_option(IPPROTO_IPV6, IPV6_ADDRFORM, &int(2)), Err(Errno::ENOPROTOOPT));

    // ICMPv6 echo: the stack answers, and the reply has the identifier of the socket.
    let p = Dgram::new6(Proto::Ping);
    let req = [128, 0, 0, 0, 0, 0, 0, 1, b'p', b'i', b'n', b'g'];
    assert_eq!(send6(&p, Some((lo, 0)), &req), Ok(12));
    let r = p.recv(100, 0, true).unwrap();
    assert_eq!(r.data[0], 129);
    assert_eq!(u16::from_be_bytes([r.data[4], r.data[5]]), name(&p.name()).1);
    assert_eq!(&r.data[6..], &[0, 1, b'p', b'i', b'n', b'g']);
    assert_eq!(send6(&p, Some((lo, 0)), &[8, 0, 0, 0, 0, 0, 0, 0]), Err(Errno::EINVAL));

    // A raw ICMPv6 socket sees the payload without the IPv6 header, and its filter drops the
    // echo replies.
    let raw = Dgram::new6(Proto::Raw(58));
    let mut filter = [0u8; 32];
    filter[16..20].copy_from_slice(&(1u32 << (129 - 128)).to_ne_bytes());
    raw.set_option(58, 1, &filter).unwrap();
    send6(&p, Some((lo, 0)), &req).unwrap();
    let r = raw.recv(200, 0, true).unwrap();
    assert_eq!(r.data[0], 128);
    assert_eq!(raw.recv(200, 0, true).err(), Some(Errno::EAGAIN));
    assert!(p.recv(100, 0, true).is_ok());

    // A routing header of type 0 with a segment left gives a parameter problem at its type, as
    // `ipv6_rthdr_rcv`. With no segment left the host takes the packet.
    let hdrincl = Dgram::new6(Proto::Raw(255));
    let packet = |left: u8| {
        let mut p = ipv6::Header::new(lo, lo, ipv6::NEXT_ROUTING, 24).to_bytes().to_vec();
        p.extend_from_slice(&[ipv6::NEXT_NONE, 2, 0, left, 0, 0, 0, 0]);
        p.extend_from_slice(&lo);
        p
    };
    assert_eq!(send6(&hdrincl, Some((lo, 0)), &packet(1)), Ok(64));
    let r = raw.recv(200, 0, true).unwrap();
    assert_eq!((r.data[0], r.data[1]), (4, 0));
    assert_eq!(u32::from_be_bytes([r.data[4], r.data[5], r.data[6], r.data[7]]), 42);
    assert_eq!(send6(&hdrincl, Some((lo, 0)), &packet(0)), Ok(64));
    assert_eq!(raw.recv(200, 0, true).err(), Some(Errno::EAGAIN));

    // TCP of IPv6, and an IPv4 connection to a dual stack listener.
    let l = Stream::new6();
    l.bind(&NoPaths, &make(&ip::ANY, 0)).unwrap();
    let port = name(&l.name()).1;
    l.listen(4).unwrap();
    let c = Stream::new6();
    assert_eq!(c.connect(&NoPaths, &make(&lo, port), true), Err(Errno::EINPROGRESS));
    assert_eq!(c.connect(&NoPaths, &make(&lo, port), true), Ok(()));
    let s = l.accept(true).unwrap();
    let s = s.as_any().downcast_ref::<Stream>().unwrap();
    assert_eq!(s.peer_name(), Ok(c.name()));
    assert_eq!(tcp_send(&c, b"tcp6"), Ok(4));
    assert_eq!(tcp_read(s, 4), b"tcp6");
    let c4 = Stream::new();
    let _ = c4.connect(&NoPaths, &sockaddr::make(ipv4::LOOPBACK, port), true);
    let s4 = l.accept(true).unwrap();
    assert_eq!(name(&s4.peer_name().unwrap()).0, ip::mapped(ipv4::LOOPBACK));
    c.release();
    s.release();
    c4.release();
    s4.release();
    l.release();
}

/// The multicast groups of a socket of IPv6: `IPV6_JOIN_GROUP`, `MCAST_JOIN_GROUP` and their
/// errors, as `ipv6_sock_mc_join` and `ipv6_sock_mc_drop` of Linux.
fn ipv6_groups() {
    use crate::mcast6;
    use rk_abi::native::in6::{IPV6_ADD_MEMBERSHIP, IPV6_DROP_MEMBERSHIP};
    use rk_abi::native::inet::IPPROTO_IPV6;
    let mreq = |g: &Ip, ifindex: i32| {
        let mut v = g.to_vec();
        v.extend_from_slice(&ifindex.to_ne_bytes());
        v
    };
    let g = v6([0xff02, 0, 0, 0, 0, 0, 0, 0x123]);
    let s = Dgram::new6(Proto::Udp);
    let t = Dgram::new6(Proto::Udp);
    let set = |s: &Dgram, name, v: &[u8]| s.set_option(IPPROTO_IPV6, name, v);
    assert_eq!(set(&s, IPV6_ADD_MEMBERSHIP, &mreq(&g, 1)[..19]), Err(Errno::EINVAL));
    assert_eq!(set(&s, IPV6_ADD_MEMBERSHIP, &mreq(&ip::LOOPBACK, 1)), Err(Errno::EINVAL));
    assert_eq!(set(&s, IPV6_ADD_MEMBERSHIP, &mreq(&g, 99)), Err(Errno::ENODEV));
    assert_eq!(set(&s, IPV6_ADD_MEMBERSHIP, &mreq(&g, 1)), Ok(()));
    assert!(mcast6::joined(1, &g));
    assert_eq!(set(&s, IPV6_ADD_MEMBERSHIP, &mreq(&g, 1)), Err(Errno::EADDRINUSE));
    assert_eq!(set(&s, IPV6_ADD_MEMBERSHIP, &mreq(&g, 0)), Err(Errno::EADDRINUSE));
    // `struct group_req`: the interface, then a `sockaddr_in6` at offset 8.
    let mut req = vec![0u8; 136];
    req[..4].copy_from_slice(&1u32.to_ne_bytes());
    req[8..10].copy_from_slice(&(rk_net::consts::AF_INET6 as u16).to_ne_bytes());
    req[16..32].copy_from_slice(&g);
    assert_eq!(set(&t, 42, &req[..135]), Err(Errno::EINVAL));
    assert_eq!(set(&t, 42, &req), Ok(()));
    // The group stays while a socket is in it.
    assert_eq!(
        set(&s, IPV6_DROP_MEMBERSHIP, &mreq(&v6([0xff02, 0, 0, 0, 0, 0, 0, 7]), 0)),
        Err(Errno::EADDRNOTAVAIL)
    );
    assert_eq!(set(&s, IPV6_DROP_MEMBERSHIP, &mreq(&g, 0)), Ok(()));
    assert_eq!(set(&s, IPV6_DROP_MEMBERSHIP, &mreq(&g, 0)), Err(Errno::EADDRNOTAVAIL));
    assert!(mcast6::joined(1, &g));
    // A socket that closes leaves its groups.
    t.release();
    assert!(!mcast6::joined(1, &g));
    s.release();
}

#[test]
fn mld_delays_and_random_identifiers() {
    use crate::mcast6::max_delay;
    let msg = |code: u16| {
        let mut m = vec![130u8, 0, 0, 0];
        m.extend_from_slice(&code.to_be_bytes());
        m
    };
    assert_eq!(max_delay(&msg(10_000), true), 10_000);
    assert_eq!(max_delay(&msg(0x8000), true), 0x8000);
    assert_eq!(max_delay(&msg(1000), false), 1000);
    // The code of MLDv2 with the exponent: (0x1000 | mant) << (exp + 3).
    assert_eq!(max_delay(&msg(0x8001), false), 0x1001 << 3);
    assert_eq!(max_delay(&msg(0xf000), false), 0x1000 << 10);
    assert_eq!(crate::mcast6::random_below(0), 0);
    assert!((0..100).all(|_| crate::mcast6::random_below(7) < 7));
}

#[test]
fn optimistic_addresses_are_sources_after_the_preferred_ones() {
    use crate::route6::{Addr6, Table6};
    use rk_abi::native::if_addr::{IFA_F_DADFAILED, IFA_F_OPTIMISTIC, IFA_F_TENTATIVE};
    let mut t = Table6::new();
    let dst = v6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1]);
    let tentative = v6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x10]);
    let optimistic = v6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x11]);
    let failed = v6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x12]);
    let mut a = Addr6::new(2, tentative, 64);
    a.flags |= IFA_F_TENTATIVE;
    t.insert_addr(a).unwrap();
    assert_eq!(t.select_src(&dst, 2), None);
    let mut a = Addr6::new(2, failed, 64);
    a.flags |= IFA_F_TENTATIVE | IFA_F_OPTIMISTIC | IFA_F_DADFAILED;
    t.insert_addr(a).unwrap();
    assert_eq!(t.select_src(&dst, 2), None);
    let mut a = Addr6::new(2, optimistic, 64);
    a.flags |= IFA_F_TENTATIVE | IFA_F_OPTIMISTIC;
    t.insert_addr(a).unwrap();
    assert_eq!(t.select_src(&dst, 2), Some(optimistic));
    // Neighbour discovery does not use an optimistic source.
    assert_eq!(t.select_src_strict(&dst, 2), None);
    // A preferred address of the same scope comes first.
    let preferred = v6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x14]);
    t.insert_addr(Addr6::new(2, preferred, 64)).unwrap();
    assert_eq!(t.select_src(&dst, 2), Some(preferred));
    assert_eq!(t.select_src_strict(&dst, 2), Some(preferred));
}

#[test]
fn reassembly_in_order_and_out_of_order() {
    use crate::frag::{Add, Reasm};
    let data: Vec<u8> = (0..40u8).collect();
    let mut r: Reasm<u32> = Reasm::new();
    assert_eq!(r.add(1, 0, true, b"head", &data[..16], 0), Add::Wait);
    assert_eq!(r.add(1, 16, true, b"x", &data[16..32], 0), Add::Wait);
    assert_eq!(
        r.add(1, 32, false, b"x", &data[32..], 0),
        Add::Done(b"head".to_vec(), data.clone())
    );
    assert!(r.is_empty());
    // The last part first, and the first part last.
    assert_eq!(r.add(2, 32, false, b"x", &data[32..], 0), Add::Wait);
    assert_eq!(r.add(2, 16, true, b"x", &data[16..32], 0), Add::Wait);
    assert_eq!(r.len(), 1);
    assert_eq!(r.add(2, 0, true, b"h", &data[..16], 0), Add::Done(b"h".to_vec(), data));
    assert!(r.is_empty());
}

#[test]
fn reassembly_drops_overlaps_and_bad_parts() {
    use crate::frag::{Add, Reasm};
    let data = [7u8; 32];
    let mut r: Reasm<u32> = Reasm::new();
    assert_eq!(r.add(1, 0, true, b"h", &data[..16], 0), Add::Wait);
    // A copy of a part is not an overlap.
    assert_eq!(r.add(1, 0, true, b"h", &data[..16], 0), Add::Wait);
    // A part that overlaps drops the queue, as RFC 5722.
    assert_eq!(r.add(1, 8, true, b"h", &data[..16], 0), Add::Fail);
    assert!(r.is_empty());
    // A part that is not the last must have a length that is a multiple of 8.
    assert_eq!(r.add(2, 0, true, b"h", &data[..10], 0), Add::Fail);
    // A part after the end is not correct.
    assert_eq!(r.add(3, 8, false, b"h", &data[..8], 0), Add::Wait);
    assert_eq!(r.add(3, 16, true, b"h", &data[..8], 0), Add::Fail);
    // The data cannot be larger than 65535 bytes.
    assert_eq!(r.add(4, 65528, false, b"h", &data[..16], 0), Add::Fail);
    assert!(r.is_empty());
}

#[test]
fn reassembly_expires() {
    use crate::frag::{Add, Reasm, TIMEOUT_MS};
    let mut r: Reasm<u32> = Reasm::new();
    assert_eq!(r.add(1, 0, true, b"h", &[0; 8], 100), Add::Wait);
    assert_eq!(r.expire(100 + TIMEOUT_MS - 1), 0);
    assert_eq!(r.expire(100 + TIMEOUT_MS), 1);
    assert!(r.is_empty());
}

#[test]
fn fragment_split() {
    use crate::frag::split;
    // 1500 - 20 gives parts of 1480 bytes.
    assert_eq!(split(4072, 1480), vec![(0, 1480), (1480, 1480), (2960, 1112)]);
    // A room that is not a multiple of 8 goes down to one.
    assert_eq!(split(20, 13), vec![(0, 8), (8, 8), (16, 4)]);
    assert_eq!(split(0, 1480), vec![(0, 0)]);
}

#[test]
fn ipv6_fragment_header() {
    use crate::ipv6::{FRAG_HLEN, Frag, HLEN, NEXT_FRAGMENT};
    let f = Frag { at: HLEN, nh: 6, next: 58, offset: 1448, more: true, id: 0x1234_5678 };
    let mut pkt = vec![0u8; HLEN];
    pkt[0] = 0x60;
    pkt[6] = NEXT_FRAGMENT;
    pkt.extend_from_slice(&f.to_bytes());
    pkt.extend_from_slice(&[0; 16]);
    assert_eq!(Frag::find(&pkt), Some(f));
    assert_eq!(f.to_bytes().len(), FRAG_HLEN);
    // A packet without a fragment header gives nothing.
    pkt[6] = 58;
    assert_eq!(Frag::find(&pkt), None);
}

#[test]
fn neighbour_admin_entries() {
    use neigh::Nud;
    let mac = MacAddr([2, 0, 0, 0, 0, 1]);
    let other = MacAddr([2, 0, 0, 0, 0, 2]);
    let key = (2, [10, 0, 0, 5]);
    let mut t: neigh::Table<u32> = neigh::Table::new();
    // A new entry needs NLM_F_CREATE.
    assert_eq!(t.add(key, Some(mac), Nud::Permanent, 0, 0), Err(Errno::ENOENT));
    assert_eq!(t.add(key, Some(mac), Nud::Permanent, 0, NLM_F_CREATE | NLM_F_EXCL), Ok(vec![]));
    assert_eq!(
        t.add(key, Some(mac), Nud::Permanent, 0, NLM_F_CREATE | NLM_F_EXCL),
        Err(Errno::EEXIST)
    );
    // ARP does not change a permanent entry.
    t.update(key, other, 1, true);
    assert_eq!(t.lookup(key), Some(mac));
    assert_eq!(t.entries(2)[0].state, Nud::Permanent);
    // Without NLM_F_REPLACE the old address stays.
    assert_eq!(t.add(key, Some(other), Nud::Permanent, 3, NLM_F_CREATE), Ok(vec![]));
    assert_eq!(t.lookup(key), Some(mac));
    assert_eq!(t.add(key, Some(other), Nud::Stale, 3, NLM_F_CREATE | NLM_F_REPLACE), Ok(vec![]));
    assert_eq!(t.lookup(key), Some(other));
    assert_eq!(t.entries(4)[0].state, Nud::Stale);
    // A permanent entry does not go away by itself.
    t.add(key, None, Nud::Permanent, 5, NLM_F_REPLACE).unwrap();
    t.tick(5 + neigh::GC_MS * 10);
    assert!(t.contains(key));
    assert!(t.remove(key));
    assert!(!t.remove(key));
    // An entry without an address is not valid.
    assert_eq!(t.add(key, None, Nud::Reachable, 6, NLM_F_CREATE), Err(Errno::EINVAL));
}

#[test]
fn neighbour_admin_entry_sends_the_queue() {
    use neigh::Nud;
    let key = (2, [10, 0, 0, 6]);
    let mut t: neigh::Table<u32> = neigh::Table::new();
    assert_eq!(t.resolve(key, 0, 7), Resolve::Wait { probe: true });
    let mac = MacAddr([2, 0, 0, 0, 0, 3]);
    assert_eq!(t.add(key, Some(mac), Nud::Reachable, 1, NLM_F_CREATE | NLM_F_REPLACE), Ok(vec![7]));
    assert!(t.remove(key));
    assert_eq!(t.resolve(key, 2, 8), Resolve::Wait { probe: true });
    assert!(t.remove(key));
    assert_eq!(t.dropped, 1);
}
