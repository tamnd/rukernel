//! The tests of the mapped rings of the packet sockets.

use super::ring::{
    self, TP_STATUS_AVAILABLE, TP_STATUS_BLK_TMO, TP_STATUS_KERNEL, TP_STATUS_SEND_REQUEST,
    TP_STATUS_TS_SOFTWARE, TP_STATUS_USER,
};
use super::*;
use crate::consts::{SOCK_DGRAM, SOCK_RAW};
use crate::{NoPaths, Socket};
use alloc::vec;
use rk_frame::addr::PAGE_SIZE;

const ALL: u16 = (ETH_P_ALL as u16).to_be();

/// A `struct tpacket_req3` as bytes. A `struct tpacket_req` is the first 16 bytes.
fn req(block: u32, blocks: u32, frame: u32, frames: u32, tov: u32, private: u32) -> Vec<u8> {
    [block, blocks, frame, frames, tov, private, 0].iter().flat_map(|v| v.to_ne_bytes()).collect()
}

fn int(v: i32) -> [u8; 4] {
    v.to_ne_bytes()
}

/// Makes a socket of `kind` for all protocols, bound to a new dummy device `name` that is up.
fn bound(kind: u32, name: &[u8]) -> (Arc<PacketSocket>, Arc<NetDevice>) {
    dev::init();
    let d = crate::dummy::create(Some(name)).unwrap();
    d.set_up(true);
    let p = PacketSocket::new(kind, u32::from(ALL)).unwrap();
    bind(&p, &d);
    (p, d)
}

fn bind(p: &PacketSocket, d: &NetDevice) {
    let mut addr = [0u8; SOCKADDR_LL];
    addr[..2].copy_from_slice(&(AF_PACKET as u16).to_ne_bytes());
    addr[2..4].copy_from_slice(&ALL.to_ne_bytes());
    addr[4..8].copy_from_slice(&d.ifindex().to_ne_bytes());
    p.bind(&NoPaths, &addr).unwrap();
}

/// An IPv4 frame to `d` with `len` bytes of payload.
fn frame(d: &NetDevice, len: usize) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&d.mac().0);
    f.extend_from_slice(&[2, 0, 0, 0, 0, 1]);
    f.extend_from_slice(&[0x08, 0x00]);
    f.extend((0..len).map(|i| i as u8));
    f
}

fn receive(d: &NetDevice, data: &[u8]) {
    tap(d, &NetBuf::from_slice(data), Direction::In);
}

fn get32(p: &PacketSocket, at: usize) -> u32 {
    p.rx.lock().as_ref().unwrap().get32(at)
}

fn get16(p: &PacketSocket, at: usize) -> u16 {
    let mut b = [0; 2];
    p.rx.lock().as_ref().unwrap().read(at, &mut b);
    u16::from_ne_bytes(b)
}

fn bytes(p: &PacketSocket, at: usize, len: usize) -> Vec<u8> {
    let mut b = vec![0; len];
    p.rx.lock().as_ref().unwrap().read(at, &mut b);
    b
}

/// `PACKET_VERSION` takes the three formats, and gives `EINVAL` for another value or size.
#[test]
fn the_version_takes_the_three_formats() {
    let p = PacketSocket::new(SOCK_RAW, 0).unwrap();
    for v in [TPACKET_V1, TPACKET_V2, TPACKET_V3] {
        assert_eq!(p.set_option(SOL_PACKET, PACKET_VERSION, &int(v)), Ok(()));
        assert_eq!(p.get_option(SOL_PACKET, PACKET_VERSION), Ok(int(v).to_vec()));
    }
    assert_eq!(p.set_option(SOL_PACKET, PACKET_VERSION, &int(3)), Err(Errno::EINVAL));
    assert_eq!(p.set_option(SOL_PACKET, PACKET_VERSION, &[0; 2]), Err(Errno::EINVAL));
    assert_eq!(p.set_option(SOL_PACKET, PACKET_RESERVE, &int(-1)), Err(Errno::EINVAL));
    assert_eq!(p.set_option(SOL_PACKET, PACKET_LOSS, &[0; 8]), Err(Errno::EINVAL));
}

/// `PACKET_HDRLEN` gives the size of the header of the version in the value.
#[test]
fn hdrlen_reads_the_version() {
    let p = PacketSocket::new(SOCK_RAW, 0).unwrap();
    assert_eq!(p.option_input(SOL_PACKET, PACKET_HDRLEN), 4);
    let get = |v: &[u8]| p.get_option_in(SOL_PACKET, PACKET_HDRLEN, v);
    assert_eq!(get(&int(TPACKET_V1)), Ok(int(32).to_vec()));
    assert_eq!(get(&int(TPACKET_V2)), Ok(int(32).to_vec()));
    assert_eq!(get(&int(TPACKET_V3)), Ok(int(48).to_vec()));
    assert_eq!(get(&int(7)), Err(Errno::EINVAL));
    assert_eq!(get(&[0; 2]), Err(Errno::EINVAL));
}

/// A ring request has the checks of `packet_set_ring` of Linux.
#[test]
fn a_ring_request_is_checked() {
    let p = PacketSocket::new(SOCK_RAW, 0).unwrap();
    let pg = PAGE_SIZE as u32;
    let set = |r: &[u8]| p.set_option(SOL_PACKET, PACKET_RX_RING, r);
    // Too short, not page aligned, a frame that is not aligned or too small, and a wrong count.
    assert_eq!(set(&req(pg, 1, 2048, 2, 0, 0)[..12]), Err(Errno::EINVAL));
    assert_eq!(set(&req(pg + 16, 1, 2048, 2, 0, 0)), Err(Errno::EINVAL));
    assert_eq!(set(&req(pg, 1, 2040, 2, 0, 0)), Err(Errno::EINVAL));
    assert_eq!(set(&req(pg, 1, 48, 85, 0, 0)), Err(Errno::EINVAL));
    assert_eq!(set(&req(pg, 2, 2048, 3, 0, 0)), Err(Errno::EINVAL));
    assert_eq!(set(&req(0x8000_0000, 1, 2048, 0x10_0000, 0, 0)), Err(Errno::EINVAL));
    // A removal with frames.
    assert_eq!(set(&req(pg, 0, 2048, 2, 0, 0)), Err(Errno::EINVAL));
    assert_eq!(set(&req(pg, 2, 2048, 4, 0, 0)), Ok(()));
    assert_eq!(set(&req(pg, 2, 2048, 4, 0, 0)), Err(Errno::EBUSY));
    assert_eq!(p.set_option(SOL_PACKET, PACKET_VERSION, &int(1)), Err(Errno::EBUSY));
    assert_eq!(p.set_option(SOL_PACKET, PACKET_RESERVE, &int(64)), Err(Errno::EBUSY));
    assert_eq!(set(&req(0, 0, 0, 0, 0, 0)), Ok(()));
    assert_eq!(p.set_option(SOL_PACKET, PACKET_RESERVE, &int(4000)), Ok(()));
    // The reserve makes the smallest frame larger than the frame.
    assert_eq!(set(&req(pg, 2, 2048, 4, 0, 0)), Err(Errno::EINVAL));
}

/// A `TPACKET_V3` request needs space for the private area, and a transmit ring of
/// `TPACKET_V3` takes no block fields.
#[test]
fn a_v3_request_checks_the_private_area() {
    let p = PacketSocket::new(SOCK_RAW, 0).unwrap();
    let pg = PAGE_SIZE as u32;
    assert_eq!(p.set_option(SOL_PACKET, PACKET_VERSION, &int(TPACKET_V3)), Ok(()));
    let rx = |r: &[u8]| p.set_option(SOL_PACKET, PACKET_RX_RING, r);
    // A `struct tpacket_req` is too short for `TPACKET_V3`.
    assert_eq!(rx(&req(pg, 2, pg, 2, 100, 0)[..16]), Err(Errno::EINVAL));
    assert_eq!(rx(&req(pg, 2, pg, 2, 100, 3 << 30)), Err(Errno::EINVAL));
    assert_eq!(rx(&req(pg, 2, pg, 2, 100, 512)), Ok(()));
    let tx = |r: &[u8]| p.set_option(SOL_PACKET, PACKET_TX_RING, r);
    assert_eq!(tx(&req(pg, 1, pg, 1, 100, 0)), Err(Errno::EINVAL));
    assert_eq!(tx(&req(pg, 1, pg, 1, 0, 0)), Ok(()));
}

/// A mapping must have the size of both rings, and a ring cannot change while it is mapped.
#[test]
fn the_mapping_has_both_rings() {
    let p = PacketSocket::new(SOCK_RAW, 0).unwrap();
    let pg = PAGE_SIZE as u32;
    assert_eq!(p.mmap(0, PAGE_SIZE).err(), Some(Errno::EINVAL));
    p.set_option(SOL_PACKET, PACKET_RX_RING, &req(pg, 2, 2048, 4, 0, 0)).unwrap();
    p.set_option(SOL_PACKET, PACKET_TX_RING, &req(2 * pg, 1, 2048, 4, 0, 0)).unwrap();
    assert_eq!(p.mmap(0, 2 * PAGE_SIZE).err(), Some(Errno::EINVAL));
    assert_eq!(p.mmap(PAGE_SIZE as u64, 4 * PAGE_SIZE).err(), Some(Errno::EINVAL));
    let map = p.mmap(0, 4 * PAGE_SIZE).unwrap();
    assert_eq!(map.pages, 4);
    let off = req(0, 0, 0, 0, 0, 0);
    assert_eq!(p.set_option(SOL_PACKET, PACKET_RX_RING, &off), Err(Errno::EBUSY));
    drop(map);
    assert_eq!(p.set_option(SOL_PACKET, PACKET_RX_RING, &off), Ok(()));
}

/// A `TPACKET_V2` receive ring gets the frames with their headers, and drops a frame when the
/// program did not give the frame at the head back.
#[test]
fn a_v2_ring_receives_frames() {
    let _serial = crate::TEST_DEVICES.lock();
    let (p, d) = bound(SOCK_RAW, b"pkring2");
    p.set_option(SOL_PACKET, PACKET_VERSION, &int(TPACKET_V2)).unwrap();
    p.set_option(SOL_PACKET, PACKET_RX_RING, &req(PAGE_SIZE as u32, 1, 2048, 2, 0, 0)).unwrap();
    assert_eq!(p.poll() & POLLIN, 0);
    let f = frame(&d, 50);
    receive(&d, &f);
    assert_ne!(p.poll() & POLLIN, 0);
    assert_eq!(get32(&p, 0), TP_STATUS_USER | TP_STATUS_TS_SOFTWARE);
    assert_eq!((get32(&p, 4), get32(&p, 8)), (64, 64));
    // The network header is at `TPACKET_ALIGN(TPACKET2_HDRLEN + 16)`, and the link header just
    // before it.
    assert_eq!((get16(&p, 12), get16(&p, 14)), (66, 80));
    assert_eq!(bytes(&p, 66, 64), f);
    // The `struct sockaddr_ll` after the header.
    assert_eq!(get16(&p, 32), AF_PACKET as u16);
    assert_eq!(get32(&p, 36), d.ifindex());
    // The second frame fills the ring, and the third finds the first frame still in use.
    receive(&d, &f);
    receive(&d, &f);
    assert_eq!(get32(&p, 2048) & TP_STATUS_USER, TP_STATUS_USER);
    let stats = p.get_option(SOL_PACKET, PACKET_STATISTICS).unwrap();
    assert_eq!(stats, [3u32.to_ne_bytes(), 1u32.to_ne_bytes()].concat());
    // The program gives the first frame back, and the next frame goes there.
    p.rx.lock().as_ref().unwrap().set_status(0, TP_STATUS_KERNEL);
    receive(&d, &f);
    assert_eq!(get32(&p, 0), TP_STATUS_USER | TP_STATUS_TS_SOFTWARE);
    dev::unregister(&d);
}

/// A `SOCK_DGRAM` socket with a `TPACKET_V1` ring gets the payload only.
#[test]
fn a_v1_ring_of_a_dgram_socket_has_the_payload() {
    let _serial = crate::TEST_DEVICES.lock();
    let (p, d) = bound(SOCK_DGRAM, b"pkring1");
    p.set_option(SOL_PACKET, PACKET_RESERVE, &int(16)).unwrap();
    p.set_option(SOL_PACKET, PACKET_RX_RING, &req(PAGE_SIZE as u32, 1, 2048, 2, 0, 0)).unwrap();
    let f = frame(&d, 30);
    receive(&d, &f);
    assert_eq!(get32(&p, 0), TP_STATUS_USER | TP_STATUS_TS_SOFTWARE);
    assert_eq!(get32(&p, 4), 0);
    assert_eq!((get32(&p, 8), get32(&p, 12)), (30, 30));
    assert_eq!((get16(&p, 16), get16(&p, 18)), (96, 96));
    assert_eq!(bytes(&p, 96, 30), f[HLEN..]);
    dev::unregister(&d);
}

/// A `TPACKET_V3` ring puts the frames one after the other in a block, and the retire timer
/// gives the block to the program.
#[test]
fn a_v3_ring_fills_blocks() {
    let _serial = crate::TEST_DEVICES.lock();
    let (p, d) = bound(SOCK_RAW, b"pkring3");
    let pg = PAGE_SIZE as u32;
    p.set_option(SOL_PACKET, PACKET_VERSION, &int(TPACKET_V3)).unwrap();
    p.set_option(SOL_PACKET, PACKET_RX_RING, &req(pg, 2, 2048, 4, 100, 0)).unwrap();
    // The block descriptor of the open block.
    assert_eq!((get32(&p, 0), get32(&p, 4), get32(&p, 8)), (2, 48, TP_STATUS_KERNEL));
    assert_eq!((get32(&p, 16), get32(&p, 20)), (48, 48));
    assert_eq!(bytes(&p, 24, 8), 1u64.to_ne_bytes());
    let f = frame(&d, 50);
    receive(&d, &f);
    receive(&d, &f);
    assert_eq!(get32(&p, 8), TP_STATUS_KERNEL);
    assert_eq!(p.poll() & POLLIN, 0);
    // A packet takes the link header at 82, then 64 bytes, rounded up to 8.
    let size = 152u32;
    assert_eq!(get32(&p, 12), 2);
    assert_eq!(get32(&p, 48), size);
    assert_eq!((get32(&p, 48 + 12), get32(&p, 48 + 16)), (64, 64));
    assert_eq!((get16(&p, 48 + 24), get16(&p, 48 + 26)), (82, 96));
    assert_eq!(bytes(&p, 48 + 82, 64), f);
    // Before the timeout the timer does nothing.
    let tov = (100 * hz()).div_ceil(1000);
    assert_eq!(p.retire(tov - 1), Some(tov));
    assert_eq!(p.retire(tov), Some(2 * tov));
    assert_eq!(get32(&p, 8), TP_STATUS_USER | TP_STATUS_BLK_TMO);
    assert_eq!(get32(&p, 48 + size as usize), 0);
    assert_eq!(get32(&p, 20), 48 + 2 * size);
    assert_ne!(p.poll() & POLLIN, 0);
    // The second block is open now.
    assert_eq!(bytes(&p, PAGE_SIZE + 24, 8), 2u64.to_ne_bytes());
    // Each packet of 2000 bytes fills the second block, and the first block is in use, so the
    // queue freezes.
    let big = frame(&d, 2000);
    receive(&d, &big);
    receive(&d, &big);
    receive(&d, &big);
    assert_eq!(get32(&p, PAGE_SIZE + 8), TP_STATUS_USER);
    assert_eq!(get32(&p, PAGE_SIZE + 12), 1);
    let stats = p.get_option(SOL_PACKET, PACKET_STATISTICS).unwrap();
    assert_eq!(stats, [5u32.to_ne_bytes(), 2u32.to_ne_bytes(), 1u32.to_ne_bytes()].concat());
    // The program gives the first block back, and the next packet opens it.
    p.rx.lock().as_ref().unwrap().set_status(8, TP_STATUS_KERNEL);
    receive(&d, &f);
    assert_eq!(get32(&p, 12), 1);
    assert_eq!(bytes(&p, 24, 8), 3u64.to_ne_bytes());
    dev::unregister(&d);
}

/// A `TPACKET_V2` transmit ring sends the frames that the program asks to send.
#[test]
fn a_v2_ring_sends_frames() {
    let _serial = crate::TEST_DEVICES.lock();
    let (p, d) = bound(SOCK_RAW, b"pktx2");
    // A second socket sees the frames that the device sends.
    let watch = PacketSocket::new(SOCK_RAW, u32::from(ALL)).unwrap();
    bind(&watch, &d);
    p.set_option(SOL_PACKET, PACKET_VERSION, &int(TPACKET_V2)).unwrap();
    p.set_option(SOL_PACKET, PACKET_TX_RING, &req(PAGE_SIZE as u32, 1, 2048, 2, 0, 0)).unwrap();
    let f = frame(&d, 50);
    {
        let tx = p.tx.lock();
        let ring = tx.as_ref().unwrap();
        for at in [0, 2048] {
            ring.write(at + 4, &64u32.to_ne_bytes());
            ring.write(at + 32, &f);
            ring.set_status(at, TP_STATUS_SEND_REQUEST);
        }
    }
    let msg = Message::default();
    assert_eq!(p.send(&NoPaths, msg, 0, true), Ok(128));
    assert_eq!(watch.recv(2048, 0, true).unwrap().data, f);
    assert_eq!(watch.recv(2048, 0, true).unwrap().data, f);
    {
        let tx = p.tx.lock();
        let ring = tx.as_ref().unwrap();
        assert_eq!(ring.status(0), TP_STATUS_AVAILABLE);
        // A frame that is too large gets `TP_STATUS_WRONG_FORMAT`.
        ring.write(4, &4000u32.to_ne_bytes());
        ring.set_status(0, TP_STATUS_SEND_REQUEST);
    }
    assert_eq!(p.send(&NoPaths, Message::default(), 0, true), Err(Errno::EMSGSIZE));
    assert_eq!(p.tx.lock().as_ref().unwrap().status(0), ring::TP_STATUS_WRONG_FORMAT);
    dev::unregister(&d);
}
