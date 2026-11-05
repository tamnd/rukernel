//! The answers of `reject`, as net/ipv4/netfilter/nf_reject_ipv4.c and
//! net/ipv6/netfilter/nf_reject_ipv6.c of Linux: an ICMP or ICMPv6 error, or a TCP RST, about a
//! packet that a rule drops.
//!
//! The stack of IPv4 and IPv6 sends the answer: it registers a function with
//! `nf_reject_set_fn`, as the masquerade of nf_nat.rs, so that rk-net does not depend on the
//! routes. This file makes the TCP segment of the RST.

use super::nf_nat::{csum_add, csum_fold};
use super::{NFPROTO_IPV4, NFPROTO_IPV6, nf_pktinfo};
use rk_frame::sync::SpinLock;

/// The answer to a packet that `reject` drops.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NfReject {
    /// An ICMP error "destination unreachable" with the code, or an ICMPv6 error "destination
    /// unreachable" with the code for IPv6.
    Unreach(u8),
    /// A TCP RST.
    TcpReset,
}

/// The TCP RST that answers a packet, as `nf_reject_ip_tcphdr_put` and
/// `nf_reject_ip6_tcphdr_put` of Linux.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NfRejectRst {
    /// The source of the RST: the destination of the packet. An IPv4 address has 4 bytes, the
    /// rest are 0.
    pub src: [u8; 16],
    /// The destination of the RST: the source of the packet.
    pub dst: [u8; 16],
    /// The TCP header of the RST, with its checksum.
    pub tcp: [u8; 20],
}

/// The function of the stack that sends the answer `how` to the packet `packet` of the family
/// `pf`, at the hook `hook`. `in_dev` is the device that the packet came in on, or 0.
pub type NfRejectFn = fn(pf: u8, hook: u8, in_dev: u32, packet: &[u8], how: NfReject);

static REJECT_FN: SpinLock<Option<NfRejectFn>> = SpinLock::new(None);

/// Registers the function that sends the answers of `reject`.
pub fn nf_reject_set_fn(f: NfRejectFn) {
    *REJECT_FN.lock() = Some(f);
}

/// Sends the answer `how` to `packet`, as `nf_send_unreach`, `nf_send_reset` and their IPv6
/// forms of Linux.
pub(super) fn nf_send_reject(pf: u8, hook: u8, in_dev: u32, packet: &[u8], how: NfReject) {
    let f = *REJECT_FN.lock();
    if let Some(f) = f {
        f(pf, hook, in_dev, packet, how);
    }
}

/// Makes the RST that answers the TCP segment in `packet`, as `nf_reject_ip_tcphdr_get` and
/// `nf_reject_ip_tcphdr_put` of Linux. Gives `None` for a packet that is not TCP, for a
/// fragment, and for an RST.
pub fn nf_reject_tcp_rst(pf: u8, packet: &[u8]) -> Option<NfRejectRst> {
    let pkt = nf_pktinfo(pf, packet);
    if pkt.l4proto != 6 {
        return None;
    }
    let th = pkt.thoff?;
    let t = packet.get(th..th + 20)?;
    let flags = t[13];
    // RST.
    if flags & 0x04 != 0 {
        return None;
    }
    let (mut src, mut dst) = ([0u8; 16], [0u8; 16]);
    let alen = match pf {
        NFPROTO_IPV4 => {
            src[..4].copy_from_slice(&packet[16..20]);
            dst[..4].copy_from_slice(&packet[12..16]);
            4
        }
        NFPROTO_IPV6 => {
            src.copy_from_slice(&packet[24..40]);
            dst.copy_from_slice(&packet[8..24]);
            16
        }
        _ => return None,
    };
    let mut r = [0u8; 20];
    r[0..2].copy_from_slice(&t[2..4]);
    r[2..4].copy_from_slice(&t[0..2]);
    r[12] = 5 << 4;
    if flags & 0x10 != 0 {
        // ACK: the RST has the sequence number of the ACK.
        r[4..8].copy_from_slice(&t[8..12]);
        r[13] = 0x04;
    } else {
        // The RST acks the segment: its data, a SYN and a FIN.
        let end = match pf {
            NFPROTO_IPV4 => usize::from(u16::from_be_bytes([packet[2], packet[3]])),
            _ => 40 + usize::from(u16::from_be_bytes([packet[4], packet[5]])),
        };
        let doff = usize::from(t[12] >> 4) * 4;
        let len = end.min(packet.len()).saturating_sub(th + doff) as u32;
        let seq = u32::from_be_bytes([t[4], t[5], t[6], t[7]]);
        let ack = seq
            .wrapping_add(len)
            .wrapping_add(u32::from(flags & 0x02 != 0))
            .wrapping_add(u32::from(flags & 0x01 != 0));
        r[8..12].copy_from_slice(&ack.to_be_bytes());
        r[13] = 0x14;
    }
    // The checksum with the pseudo header.
    let mut s = csum_add(0, &src[..alen]);
    s = csum_add(s, &dst[..alen]);
    s = csum_add(s, &[0, 6, 0, 20]);
    s = csum_add(s, &r);
    r[16..18].copy_from_slice(&csum_fold(s).to_be_bytes());
    Some(NfRejectRst { src, dst, tcp: r })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn tcp4(flags: u8, payload: usize) -> alloc::vec::Vec<u8> {
        let mut p = vec![0u8; 40 + payload];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&((40 + payload) as u16).to_be_bytes());
        p[9] = 6;
        p[12..16].copy_from_slice(&[10, 0, 0, 1]);
        p[16..20].copy_from_slice(&[10, 0, 0, 2]);
        p[20..22].copy_from_slice(&1000u16.to_be_bytes());
        p[22..24].copy_from_slice(&80u16.to_be_bytes());
        p[24..28].copy_from_slice(&100u32.to_be_bytes());
        p[28..32].copy_from_slice(&555u32.to_be_bytes());
        p[32] = 5 << 4;
        p[33] = flags;
        p
    }

    fn sum_ok(r: &NfRejectRst, alen: usize) -> bool {
        let mut s = csum_add(0, &r.src[..alen]);
        s = csum_add(s, &r.dst[..alen]);
        s = csum_add(s, &[0, 6, 0, 20]);
        csum_fold(csum_add(s, &r.tcp)) == 0
    }

    #[test]
    fn the_rst_of_a_syn_acks_it_and_the_rst_of_an_ack_takes_its_number() {
        let r = nf_reject_tcp_rst(NFPROTO_IPV4, &tcp4(0x02, 0)).unwrap();
        assert_eq!((&r.src[..4], &r.dst[..4]), (&[10, 0, 0, 2][..], &[10, 0, 0, 1][..]));
        assert_eq!(&r.tcp[0..4], &[0, 80, 0x03, 0xe8]);
        assert_eq!(r.tcp[4..8], [0; 4]);
        assert_eq!(r.tcp[8..12], 101u32.to_be_bytes());
        assert_eq!(r.tcp[13], 0x14);
        assert!(sum_ok(&r, 4));
        // Data with a FIN: the ack is after the data and the FIN.
        let r = nf_reject_tcp_rst(NFPROTO_IPV4, &tcp4(0x01, 7)).unwrap();
        assert_eq!(r.tcp[8..12], 108u32.to_be_bytes());
        let r = nf_reject_tcp_rst(NFPROTO_IPV4, &tcp4(0x10, 3)).unwrap();
        assert_eq!((&r.tcp[4..8], r.tcp[13]), (&555u32.to_be_bytes()[..], 0x04));
        assert!(sum_ok(&r, 4));
        // No RST answers an RST or a packet that is not TCP.
        assert_eq!(nf_reject_tcp_rst(NFPROTO_IPV4, &tcp4(0x04, 0)), None);
        let mut udp = tcp4(0x02, 0);
        udp[9] = 17;
        assert_eq!(nf_reject_tcp_rst(NFPROTO_IPV4, &udp), None);
    }

    #[test]
    fn the_rst_of_ipv6_has_the_addresses_of_ipv6() {
        let mut p = vec![0u8; 60];
        p[0] = 0x60;
        p[4..6].copy_from_slice(&20u16.to_be_bytes());
        p[6] = 6;
        p[23] = 1;
        p[39] = 2;
        p[44..48].copy_from_slice(&9u32.to_be_bytes());
        p[52] = 5 << 4;
        p[53] = 0x02;
        let r = nf_reject_tcp_rst(NFPROTO_IPV6, &p).unwrap();
        assert_eq!((r.src[15], r.dst[15]), (2, 1));
        assert_eq!(r.tcp[8..12], 10u32.to_be_bytes());
        assert!(sum_ok(&r, 16));
    }
}
