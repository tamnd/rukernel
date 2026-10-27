use super::msg::{self, Attrs, Builder, HDRLEN, Header};
use super::{ADDR_LEN, NetlinkSocket, link};
use crate::consts::{AF_NETLINK, IFF_UP, MSG_TRUNC, SOCK_DGRAM, SOCK_RAW, SOCK_STREAM};
use crate::{Message, NoPaths, Socket, dev};
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_abi::native::if_link::{IFLA_IFNAME, IFLA_MTU};
use rk_abi::native::netlink::{
    NETLINK_ROUTE, NLM_F_ACK, NLM_F_CAPPED, NLM_F_DUMP, NLM_F_MULTI, NLM_F_REQUEST, NLMSG_DONE,
    NLMSG_ERROR,
};
use rk_abi::native::rtnetlink::{RTM_GETLINK, RTM_NEWLINK, RTM_SETLINK, RTNLGRP_LINK};

fn addr(portid: u32, groups: u32) -> Vec<u8> {
    super::sockaddr(portid, groups)
}

fn socket() -> alloc::sync::Arc<NetlinkSocket> {
    dev::init();
    super::init();
    NetlinkSocket::new(SOCK_RAW, NETLINK_ROUTE).unwrap()
}

fn send(s: &NetlinkSocket, data: Vec<u8>) {
    let m = Message { data, ..Message::default() };
    s.send(&NoPaths, m, 0, true).unwrap();
}

/// A request with an `ifinfomsg` for the index `index` and the flags `flags`.
fn link_req(ty: u32, flags: u32, index: i32, ifi_flags: u32, change: u32) -> Builder {
    let mut b = Builder::new(ty as u16, (NLM_F_REQUEST | flags) as u16, 7, 0);
    let mut ifi = [0u8; link::IFINFO_LEN];
    ifi[4..8].copy_from_slice(&index.to_ne_bytes());
    ifi[8..12].copy_from_slice(&ifi_flags.to_ne_bytes());
    ifi[12..16].copy_from_slice(&change.to_ne_bytes());
    b.fixed(&ifi);
    b
}

fn recv_all(s: &NetlinkSocket) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    while let Ok(r) = s.recv(65536, 0, true) {
        out.push(r.data);
    }
    out
}

#[test]
fn a_builder_pads_each_attribute_to_4_bytes() {
    let mut b = Builder::new(16, 0, 1, 2);
    b.fixed(&[1, 2, 3]).u8(1, 9).str(3, "lo").u32(4, 0x0102_0304);
    let m = b.finish();
    assert_eq!(m.len(), HDRLEN + 4 + 8 + 8 + 8);
    let h = Header::parse(&m).unwrap();
    assert_eq!((h.len as usize, h.ty, h.seq, h.pid), (m.len(), 16, 1, 2));
    // The fixed header has a zero pad byte, and the `u8` attribute has a length of 5.
    assert_eq!(&m[HDRLEN..HDRLEN + 4], &[1, 2, 3, 0]);
    assert_eq!(u16::from_ne_bytes([m[20], m[21]]), 5);
    let attrs = Attrs::parse(&m[HDRLEN + 4..], 4);
    assert_eq!(attrs.u8(1), Ok(Some(9)));
    assert_eq!(attrs.str(3), Some(&b"lo"[..]));
    assert_eq!(attrs.u32(4), Ok(Some(0x0102_0304)));
    assert!(!attrs.has(2));
}

#[test]
fn a_nest_has_the_length_of_its_attributes() {
    let mut b = Builder::new(16, 0, 0, 0);
    let at = b.nest(5);
    b.u32(1, 1).u32(2, 2);
    b.end_nest(at);
    let empty = b.nest(6);
    b.truncate(empty);
    let m = b.finish();
    assert_eq!(m.len(), HDRLEN + 4 + 16);
    assert_eq!(u16::from_ne_bytes([m[16], m[17]]), 20);
    let inner: Vec<_> = msg::attrs(&m[HDRLEN + 4..]).collect();
    assert_eq!(inner.len(), 2);
}

#[test]
fn a_short_attribute_gives_erange() {
    let mut b = Builder::new(16, 0, 0, 0);
    b.u8(1, 1);
    let m = b.finish();
    let attrs = Attrs::parse(&m[HDRLEN..], 1);
    assert_eq!(attrs.u32(1), Err(Errno::ERANGE));
}

#[test]
fn an_ack_has_the_header_of_the_request_and_an_error_has_all_of_it() {
    let mut b = Builder::new(RTM_GETLINK as u16, (NLM_F_REQUEST | NLM_F_ACK) as u16, 42, 0);
    b.fixed(&[0; 16]);
    let req = b.finish();
    let a = msg::ack(&req, 0, 99, false);
    let h = Header::parse(&a).unwrap();
    assert_eq!(h.ty, NLMSG_ERROR as u16);
    assert_eq!(h.flags, NLM_F_CAPPED as u16);
    assert_eq!((h.seq, h.pid, h.len as usize), (42, 99, HDRLEN + 4 + HDRLEN));
    let e = msg::ack(&req, -22, 99, false);
    assert_eq!(e.len(), HDRLEN + 4 + req.len());
    assert_eq!(i32::from_ne_bytes([e[16], e[17], e[18], e[19]]), -22);
    assert_eq!(&e[20..], &req[..]);
    assert_eq!(msg::ack(&req, -22, 99, true).len(), HDRLEN + 4 + HDRLEN);
    let d = msg::done(42, 99, 0);
    let h = Header::parse(&d).unwrap();
    assert_eq!((h.ty, h.flags, h.len), (NLMSG_DONE as u16, NLM_F_MULTI as u16, 20));
}

#[test]
fn messages_stop_at_a_bad_length() {
    let mut a = Builder::new(16, 0, 1, 0);
    a.fixed(&[1]);
    let mut data = a.finish();
    data.extend_from_slice(&[0xff; 16]);
    assert_eq!(msg::messages(&data).count(), 1);
}

#[test]
fn only_raw_and_datagram_sockets_of_netlink_route_exist() {
    assert!(NetlinkSocket::new(SOCK_DGRAM, NETLINK_ROUTE).is_ok());
    assert_eq!(NetlinkSocket::new(SOCK_STREAM, NETLINK_ROUTE).err(), Some(Errno::ESOCKTNOSUPPORT));
    assert_eq!(NetlinkSocket::new(SOCK_RAW, 99).err(), Some(Errno::EPROTONOSUPPORT));
}

#[test]
fn bind_sets_the_port_id_and_the_groups() {
    let s = socket();
    let g = 1 << (RTNLGRP_LINK - 1);
    s.bind(&NoPaths, &addr(0, g)).unwrap();
    let name = s.name();
    assert_eq!(name.len(), ADDR_LEN);
    assert_eq!(u16::from_ne_bytes([name[0], name[1]]), AF_NETLINK as u16);
    let portid = u32::from_ne_bytes([name[4], name[5], name[6], name[7]]);
    assert_ne!(portid, 0);
    assert_eq!(u32::from_ne_bytes([name[8], name[9], name[10], name[11]]), g);
    // A second socket cannot take the same port ID.
    let t = socket();
    assert_eq!(t.bind(&NoPaths, &addr(portid, 0)), Err(Errno::EADDRINUSE));
    assert_eq!(s.bind(&NoPaths, &addr(portid + 1, 0)), Err(Errno::EINVAL));
    assert_eq!(s.bind(&NoPaths, &[0; 4]), Err(Errno::EINVAL));
}

#[test]
fn a_link_dump_has_the_loopback_device_and_ends_with_done() {
    let _serial = crate::TEST_DEVICES.lock();
    let s = socket();
    send(&s, link_req(RTM_GETLINK, NLM_F_DUMP, 0, 0, 0).finish());
    let dgrams = recv_all(&s);
    assert!(dgrams.len() >= 2);
    let mut names = Vec::new();
    for d in &dgrams[..dgrams.len() - 1] {
        for m in msg::messages(d) {
            let h = Header::parse(m).unwrap();
            assert_eq!(h.ty, RTM_NEWLINK as u16);
            assert_eq!(h.flags, NLM_F_MULTI as u16);
            assert_eq!(h.seq, 7);
            let attrs = Attrs::parse(&m[HDRLEN + link::IFINFO_LEN..], 69);
            names.push(attrs.str(IFLA_IFNAME).unwrap().to_vec());
        }
    }
    assert!(names.iter().any(|n| n == b"lo"));
    // `NLMSG_DONE` comes alone in the last datagram.
    let last = dgrams.last().unwrap();
    assert_eq!(last.len(), 20);
    assert_eq!(Header::parse(last).unwrap().ty, NLMSG_DONE as u16);
}

#[test]
fn a_short_receive_truncates_the_datagram() {
    let s = socket();
    send(&s, link_req(RTM_GETLINK, 0, 1, 0, 0).finish());
    let r = s.recv(8, 0, true).unwrap();
    assert_eq!(r.data.len(), 8);
    assert!(r.len > 8);
    assert_eq!(r.flags & MSG_TRUNC, MSG_TRUNC);
}

#[test]
fn getlink_of_an_unknown_index_gives_enodev() {
    let s = socket();
    send(&s, link_req(RTM_GETLINK, 0, 9999, 0, 0).finish());
    let d = s.recv(4096, 0, true).unwrap().data;
    let h = Header::parse(&d).unwrap();
    assert_eq!(h.ty, NLMSG_ERROR as u16);
    assert_eq!(i32::from_ne_bytes([d[16], d[17], d[18], d[19]]), -i32::from(Errno::ENODEV.get()));
}

#[test]
fn setlink_changes_the_mtu_and_sends_an_ack() {
    let _serial = crate::TEST_DEVICES.lock();
    let s = socket();
    let lo = dev::by_name("lo").unwrap();
    let old = lo.mtu();
    let mut b = link_req(RTM_SETLINK, NLM_F_ACK, lo.ifindex() as i32, 0, 0);
    b.u32(IFLA_MTU as u16, 1500);
    send(&s, b.finish());
    let d = s.recv(4096, 0, true).unwrap().data;
    assert_eq!(Header::parse(&d).unwrap().ty, NLMSG_ERROR as u16);
    assert_eq!(i32::from_ne_bytes([d[16], d[17], d[18], d[19]]), 0);
    assert_eq!(lo.mtu(), 1500);
    lo.set_mtu(old).unwrap();
}

#[test]
fn a_link_change_goes_to_the_link_group() {
    let _serial = crate::TEST_DEVICES.lock();
    let s = socket();
    s.bind(&NoPaths, &addr(0, 1 << (RTNLGRP_LINK - 1))).unwrap();
    let lo = dev::by_name("lo").unwrap();
    let up = lo.is_up();
    recv_all(&s);
    lo.change_flags(lo.flags() ^ IFF_UP).unwrap();
    lo.change_flags(if up { lo.flags() | IFF_UP } else { lo.flags() & !IFF_UP }).unwrap();
    let got = recv_all(&s);
    assert!(!got.is_empty());
    let h = Header::parse(&got[0]).unwrap();
    assert_eq!(h.ty, RTM_NEWLINK as u16);
    let r = s.recv(16, 0, true);
    assert!(r.is_err());
}
