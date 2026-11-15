//! The passive OS fingerprinting, as net/netfilter/nfnetlink_osf.c of Linux. A program such as
//! `nfnl_osf` loads the fingerprints of pf.os with `OSF_MSG_ADD` of the subsystem
//! `NFNL_SUBSYS_OSF`, and the expression `osf` of nf_tables finds the fingerprint of a TCP SYN
//! with `nf_osf_find`.
//!
//! A fingerprint has the length of the IP packet, the TTL, the DF bit, the window and the TCP
//! options of the SYN of a system. The lists of the fingerprints are by the DF bit, as
//! `nf_osf_fingers` of Linux.

use crate::netlink::msg::Attrs;
use crate::netlink::nfnetlink::{
    NFNL_SUBSYS_OSF, NfnlCallback, NfnlCbType, NfnlInfo, NfnlSubsystem,
};
use alloc::boxed::Box;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_abi::native::netlink::{NLM_F_CREATE, NLM_F_EXCL};
use rk_frame::sync::SpinLock;
use rk_vfs::inode::Result;

// <linux/netfilter/nfnetlink_osf.h>. The messages are `OSF_MSG_ADD` (0) and `OSF_MSG_REMOVE`
// (1), the indexes of `NFNL_OSF_CALLBACKS`.
const OSF_ATTR_FINGER: u32 = 1;
/// `OSF_ATTR_MAX`, the end of `enum nf_osf_attr_type`, that Linux gives as the highest type.
const OSF_ATTR_MAX: u16 = 2;
/// `MAXGENRELEN`: the size of the genre, the version and the subtype.
const MAXGENRELEN: usize = 32;
/// `MAX_IPOPTLEN`: the most options of a fingerprint, and the most bytes of options.
const MAX_IPOPTLEN: usize = 40;
/// The size of `struct nf_osf_user_finger`.
pub(crate) const NF_OSF_FINGER_LEN: usize = 16 + 3 * MAXGENRELEN + MAX_IPOPTLEN * 12;
const OSFOPT_MSS: u16 = 2;
const OSF_WSS_PLAIN: u32 = 0;
const OSF_WSS_MSS: u32 = 1;
const OSF_WSS_MTU: u32 = 2;
const OSF_WSS_MODULO: u32 = 3;
const OSF_WSS_MAX: u32 = 4;
/// The TTL of the packet must be the one of the fingerprint, `NF_OSF_TTL_TRUE`.
pub(crate) const NF_OSF_TTL_TRUE: u8 = 0;
/// The TTL is not checked, `NF_OSF_TTL_NOCHECK`.
pub(crate) const NF_OSF_TTL_NOCHECK: u8 = 2;
/// The MSS that some modems put in place of the one of the system.
const SMART_MSS_1: u32 = 1460;
const SMART_MSS_2: u32 = 1448;
const IP_DF: u16 = 0x4000;
const IPPROTO_TCP: u8 = 6;

/// A fingerprint, `struct nf_osf_user_finger` of Linux in the byte order of the host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NfOsfFinger {
    raw: Box<[u8; NF_OSF_FINGER_LEN]>,
}

fn ne16(d: &[u8], at: usize) -> u16 {
    u16::from_ne_bytes([d[at], d[at + 1]])
}

fn ne32(d: &[u8], at: usize) -> u32 {
    u32::from_ne_bytes([d[at], d[at + 1], d[at + 2], d[at + 3]])
}

fn be16(d: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([d[at], d[at + 1]])
}

/// The string before the NUL of a field of `MAXGENRELEN` bytes.
fn cstr(f: &[u8]) -> &[u8] {
    &f[..f.iter().position(|&c| c == 0).unwrap_or(f.len())]
}

impl NfOsfFinger {
    /// Reads the fingerprint of `OSF_ATTR_FINGER`, with the checks of
    /// `nfnl_osf_add_callback` of Linux: at most `MAX_IPOPTLEN` options, and a NUL in the
    /// genre, the subtype and the version.
    pub(crate) fn parse(d: &[u8]) -> Result<Self> {
        // `.len = sizeof(struct nf_osf_user_finger)` of the policy.
        let raw: [u8; NF_OSF_FINGER_LEN] =
            d.get(..NF_OSF_FINGER_LEN).ok_or(Errno::ERANGE)?.try_into().unwrap();
        let f = Self { raw: Box::new(raw) };
        if usize::from(f.opt_num()) > MAX_IPOPTLEN {
            return Err(Errno::EINVAL);
        }
        for at in [16, 16 + MAXGENRELEN, 16 + 2 * MAXGENRELEN] {
            if !f.raw[at..at + MAXGENRELEN].contains(&0) {
                return Err(Errno::EINVAL);
            }
        }
        Ok(f)
    }

    fn wss(&self) -> (u32, u32) {
        (ne32(&self.raw[..], 0), ne32(&self.raw[..], 4))
    }

    fn ttl(&self) -> u8 {
        self.raw[8]
    }

    fn df(&self) -> bool {
        self.raw[9] != 0
    }

    fn ss(&self) -> u16 {
        ne16(&self.raw[..], 10)
    }

    fn opt_num(&self) -> u16 {
        ne16(&self.raw[..], 14)
    }

    /// The genre, as `Linux`.
    pub(crate) fn genre(&self) -> &[u8] {
        cstr(&self.raw[16..16 + MAXGENRELEN])
    }

    /// The version, as `2.6`.
    pub(crate) fn version(&self) -> &[u8] {
        cstr(&self.raw[16 + MAXGENRELEN..16 + 2 * MAXGENRELEN])
    }

    /// The kind and the length of the option `i`.
    fn opt(&self, i: usize) -> (u16, u16) {
        let at = 16 + 3 * MAXGENRELEN + i * 12;
        (ne16(&self.raw[..], at), ne16(&self.raw[..], at + 2))
    }
}

/// The fields of the SYN that a fingerprint matches, as `struct nf_osf_hdr_ctx` of Linux.
struct NfOsfHdrCtx<'a> {
    df: bool,
    window: u16,
    totlen: u16,
    ttl: u8,
    saddr: [u8; 4],
    opts: &'a [u8],
}

/// Reads the IPv4 packet `d` (from its IP header), as `nf_osf_hdr_ctx_init` of Linux. Gives
/// `None` if the packet is not a TCP SYN with all of its header.
fn nf_osf_hdr_ctx_init(d: &[u8]) -> Option<NfOsfHdrCtx<'_>> {
    if d.len() < 20 || d[9] != IPPROTO_TCP {
        return None;
    }
    let ihl = usize::from(d[0] & 0xf) * 4;
    let tcp = d.get(ihl..ihl + 20)?;
    if tcp[13] & 0x02 == 0 {
        return None;
    }
    let doff = usize::from(tcp[12] >> 4) * 4;
    let opts = if doff > 20 { d.get(ihl + 20..ihl + doff)? } else { &[] };
    Some(NfOsfHdrCtx {
        df: be16(d, 6) & IP_DF != 0,
        window: be16(tcp, 14),
        totlen: be16(d, 2),
        ttl: d[8],
        saddr: [d[12], d[13], d[14], d[15]],
        opts,
    })
}

/// Tells if the IPv4 address is in the subnet of an address of the device `ifindex`, as
/// `inet_ifa_match` of Linux on each address of the device.
pub type NfOsfSubnetFn = fn(ifindex: u32, addr: [u8; 4]) -> bool;

static SUBNET_FN: SpinLock<Option<NfOsfSubnetFn>> = SpinLock::new(None);

/// Registers the check of the subnets of a device for `nf_osf_ttl`.
pub fn nf_osf_set_subnet_fn(f: NfOsfSubnetFn) {
    *SUBNET_FN.lock() = Some(f);
}

/// Checks the TTL of the packet against the TTL `f_ttl` of a fingerprint, as `nf_osf_ttl` of
/// Linux. With `NF_OSF_TTL_LESS`, a TTL above the one of the fingerprint is good only for a
/// packet of a subnet of the device `dev`, where no router took a hop off it.
fn nf_osf_ttl(ctx: &NfOsfHdrCtx<'_>, ttl_check: u8, f_ttl: u8, dev: u32) -> bool {
    match ttl_check {
        NF_OSF_TTL_TRUE => ctx.ttl == f_ttl,
        NF_OSF_TTL_NOCHECK => true,
        _ if ctx.ttl <= f_ttl => true,
        _ => {
            let subnet = *SUBNET_FN.lock();
            subnet.is_some_and(|s| s(dev, ctx.saddr)) && ctx.ttl == f_ttl
        }
    }
}

/// Tells if the SYN of `ctx` matches the fingerprint `f`, as `nf_osf_match_one` of Linux.
fn nf_osf_match_one(f: &NfOsfFinger, ttl_check: u8, ctx: &NfOsfHdrCtx<'_>, dev: u32) -> bool {
    if ctx.totlen != f.ss() || !nf_osf_ttl(ctx, ttl_check, f.ttl(), dev) {
        return false;
    }
    let (wc, val) = f.wss();
    if wc >= OSF_WSS_MAX {
        return false;
    }
    let n = usize::from(f.opt_num());
    let foptsize: usize = (0..n).map(|i| usize::from(f.opt(i).1)).sum();
    if foptsize > MAX_IPOPTLEN || ctx.opts.len() != foptsize {
        return false;
    }
    // The options of the SYN must be the ones of the fingerprint, in the same order.
    let mut p = 0;
    let mut mss = 0u32;
    for i in 0..n {
        let (kind, len) = f.opt(i);
        if ctx.opts.get(p).map(|&k| u16::from(k)) != Some(kind) {
            return false;
        }
        if kind == OSFOPT_MSS {
            mss = u32::from(ctx.opts.get(p + 2..p + 4).map_or(0, |m| be16(m, 0)));
        }
        p += usize::from(len);
    }
    let window = u32::from(ctx.window);
    let times = |m: u32| window == val.wrapping_mul(m);
    match wc {
        OSF_WSS_PLAIN => val == 0 || window == val,
        // Some modems lower the MSS to `SMART_MSS_2`, so the standard and the lower MSS match
        // too.
        OSF_WSS_MSS => times(mss) || times(SMART_MSS_1) || times(SMART_MSS_2),
        OSF_WSS_MTU => times(mss + 40) || times(SMART_MSS_1 + 40) || times(SMART_MSS_2 + 40),
        // Linux divides by 0 for a value of 0; here such a fingerprint matches no packet.
        OSF_WSS_MODULO => val != 0 && window % val == 0,
        _ => false,
    }
}

/// The fingerprints, by the DF bit, as `nf_osf_fingers` of Linux.
type NfOsfFingers = [Vec<NfOsfFinger>; 2];

static NF_OSF_FINGERS: SpinLock<NfOsfFingers> = SpinLock::new([Vec::new(), Vec::new()]);

/// Finds the first fingerprint that the IPv4 TCP SYN `d` (from its IP header) matches, as
/// `nf_osf_find` of Linux, and gives its genre and its version. `dev` is the device that the
/// packet came in on.
pub(crate) fn nf_osf_find(d: &[u8], ttl_check: u8, dev: u32) -> Option<(Vec<u8>, Vec<u8>)> {
    let fingers = NF_OSF_FINGERS.lock();
    nf_osf_find_in(&fingers, d, ttl_check, dev)
}

fn nf_osf_find_in(
    fingers: &NfOsfFingers,
    d: &[u8],
    ttl_check: u8,
    dev: u32,
) -> Option<(Vec<u8>, Vec<u8>)> {
    let ctx = nf_osf_hdr_ctx_init(d)?;
    fingers[usize::from(ctx.df)]
        .iter()
        .find(|f| nf_osf_match_one(f, ttl_check, &ctx, dev))
        .map(|f| (f.genre().to_vec(), f.version().to_vec()))
}

/// Checks the length of `OSF_ATTR_FINGER`, as `nfnl_osf_policy` of Linux before the handler.
fn nf_osf_policy(f: Option<&[u8]>) -> Result<()> {
    match f {
        Some(f) if f.len() < NF_OSF_FINGER_LEN => Err(Errno::ERANGE),
        _ => Ok(()),
    }
}

/// Adds the fingerprint `f`, as `nfnl_osf_add_callback` of Linux. The same fingerprint again
/// gives `EEXIST` with `NLM_F_EXCL`, and nothing without.
fn nf_osf_add(fingers: &mut NfOsfFingers, f: Option<&[u8]>, flags: u16) -> Result<()> {
    nf_osf_policy(f)?;
    let f = f.ok_or(Errno::EINVAL)?;
    if flags & NLM_F_CREATE as u16 == 0 {
        return Err(Errno::EINVAL);
    }
    let f = NfOsfFinger::parse(f)?;
    let list = &mut fingers[usize::from(f.df())];
    if list.contains(&f) {
        return if flags & NLM_F_EXCL as u16 != 0 { Err(Errno::EEXIST) } else { Ok(()) };
    }
    list.push(f);
    Ok(())
}

/// Removes the fingerprint `f`, as `nfnl_osf_remove_callback` of Linux.
fn nf_osf_remove(fingers: &mut NfOsfFingers, f: Option<&[u8]>) -> Result<()> {
    nf_osf_policy(f)?;
    let f = NfOsfFinger::parse(f.ok_or(Errno::EINVAL)?)?;
    let list = &mut fingers[usize::from(f.df())];
    let at = list.iter().position(|s| *s == f).ok_or(Errno::ENOENT)?;
    list.remove(at);
    Ok(())
}

fn nfnl_osf_add_callback(info: &NfnlInfo<'_>, tb: &Attrs<'_>) -> Result<()> {
    nf_osf_add(&mut NF_OSF_FINGERS.lock(), tb.get(OSF_ATTR_FINGER), info.nlh.flags)
}

fn nfnl_osf_remove_callback(_info: &NfnlInfo<'_>, tb: &Attrs<'_>) -> Result<()> {
    nf_osf_remove(&mut NF_OSF_FINGERS.lock(), tb.get(OSF_ATTR_FINGER))
}

static NFNL_OSF_CALLBACKS: [NfnlCallback; 2] = [
    NfnlCallback {
        call: Some(nfnl_osf_add_callback),
        dump: None,
        kind: NfnlCbType::Mutex,
        attr_count: OSF_ATTR_MAX,
    },
    NfnlCallback {
        call: Some(nfnl_osf_remove_callback),
        dump: None,
        kind: NfnlCbType::Mutex,
        attr_count: OSF_ATTR_MAX,
    },
];

/// The subsystem `NFNL_SUBSYS_OSF`, as `nfnl_osf_subsys` of Linux.
pub static NFNL_OSF_SUBSYS: NfnlSubsystem =
    NfnlSubsystem { name: "osf", subsys_id: NFNL_SUBSYS_OSF, cb: &NFNL_OSF_CALLBACKS, begin: None };

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    const OSFOPT_NOP: u16 = 1;
    const OSFOPT_WSO: u16 = 3;
    const OSFOPT_SACKP: u16 = 4;
    const OSFOPT_TS: u16 = 8;

    /// A fingerprint: the window, the TTL, the DF bit, the length of the SYN, and the options.
    fn finger(
        wss: (u32, u32),
        ttl: u8,
        df: bool,
        ss: u16,
        genre: &str,
        opts: &[(u16, u16)],
    ) -> Vec<u8> {
        let mut f = vec![0u8; NF_OSF_FINGER_LEN];
        f[0..4].copy_from_slice(&wss.0.to_ne_bytes());
        f[4..8].copy_from_slice(&wss.1.to_ne_bytes());
        f[8] = ttl;
        f[9] = u8::from(df);
        f[10..12].copy_from_slice(&ss.to_ne_bytes());
        f[14..16].copy_from_slice(&(opts.len() as u16).to_ne_bytes());
        f[16..16 + genre.len()].copy_from_slice(genre.as_bytes());
        f[48..51].copy_from_slice(b"2.6");
        for (i, (kind, len)) in opts.iter().enumerate() {
            let at = 112 + i * 12;
            f[at..at + 2].copy_from_slice(&kind.to_ne_bytes());
            f[at + 2..at + 4].copy_from_slice(&len.to_ne_bytes());
        }
        f
    }

    /// A SYN of Linux: MSS 1460, SACK permitted, a timestamp, a NOP and a window scale of 7,
    /// with a window of 64240 (44 times 1460) and the DF bit.
    fn syn(ttl: u8, flags: u8) -> Vec<u8> {
        let mut p = vec![0u8; 60];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&60u16.to_be_bytes());
        p[6] = 0x40;
        p[8] = ttl;
        p[9] = IPPROTO_TCP;
        p[12..16].copy_from_slice(&[10, 0, 0, 1]);
        p[16..20].copy_from_slice(&[10, 0, 0, 2]);
        let t = &mut p[20..];
        t[12] = 10 << 4;
        t[13] = flags;
        t[14..16].copy_from_slice(&64240u16.to_be_bytes());
        t[20..40]
            .copy_from_slice(&[2, 4, 0x05, 0xb4, 4, 2, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0, 1, 3, 3, 7]);
        p
    }

    fn linux() -> Vec<u8> {
        let opts =
            [(OSFOPT_MSS, 4), (OSFOPT_SACKP, 2), (OSFOPT_TS, 10), (OSFOPT_NOP, 1), (OSFOPT_WSO, 3)];
        finger((OSF_WSS_MSS, 44), 64, true, 60, "Linux", &opts)
    }

    #[test]
    fn a_syn_of_linux_has_the_fingerprint_of_linux() {
        let mut l: NfOsfFingers = Default::default();
        nf_osf_add(&mut l, Some(&linux()), NLM_F_CREATE as u16).unwrap();
        let found = nf_osf_find_in(&l, &syn(64, 0x02), NF_OSF_TTL_TRUE, 1);
        assert_eq!(found, Some((b"Linux".to_vec(), b"2.6".to_vec())));
        // An other TTL, a packet that is not a SYN, or no DF bit.
        assert_eq!(nf_osf_find_in(&l, &syn(63, 0x02), NF_OSF_TTL_TRUE, 1), None);
        assert!(nf_osf_find_in(&l, &syn(63, 0x02), NF_OSF_TTL_NOCHECK, 1).is_some());
        assert_eq!(nf_osf_find_in(&l, &syn(64, 0x10), NF_OSF_TTL_NOCHECK, 1), None);
        let mut nodf = syn(64, 0x02);
        nodf[6] = 0;
        assert_eq!(nf_osf_find_in(&l, &nodf, NF_OSF_TTL_TRUE, 1), None);
        // The options in an other order.
        let mut other = syn(64, 0x02);
        other[40..44].copy_from_slice(&[4, 2, 2, 4]);
        assert_eq!(nf_osf_find_in(&l, &other, NF_OSF_TTL_TRUE, 1), None);
    }

    #[test]
    fn a_fingerprint_is_added_once_and_removed_once() {
        let mut l: NfOsfFingers = Default::default();
        let f = linux();
        assert_eq!(nf_osf_add(&mut l, Some(&f), 0), Err(Errno::EINVAL));
        assert_eq!(nf_osf_add(&mut l, Some(&f[..100]), 0), Err(Errno::ERANGE));
        assert_eq!(nf_osf_add(&mut l, None, NLM_F_CREATE as u16), Err(Errno::EINVAL));
        assert_eq!(nf_osf_add(&mut l, Some(&f[..100]), NLM_F_CREATE as u16), Err(Errno::ERANGE));
        nf_osf_add(&mut l, Some(&f), NLM_F_CREATE as u16).unwrap();
        nf_osf_add(&mut l, Some(&f), NLM_F_CREATE as u16).unwrap();
        let excl = (NLM_F_CREATE | NLM_F_EXCL) as u16;
        assert_eq!(nf_osf_add(&mut l, Some(&f), excl), Err(Errno::EEXIST));
        assert_eq!((l[0].len(), l[1].len()), (0, 1));
        nf_osf_remove(&mut l, Some(&f)).unwrap();
        assert_eq!(nf_osf_remove(&mut l, Some(&f)), Err(Errno::ENOENT));
        // A genre with no NUL, and too many options.
        let mut bad = f.clone();
        bad[16..48].fill(b'a');
        assert_eq!(nf_osf_add(&mut l, Some(&bad), NLM_F_CREATE as u16), Err(Errno::EINVAL));
        let mut bad = f;
        bad[14..16].copy_from_slice(&41u16.to_ne_bytes());
        assert_eq!(nf_osf_add(&mut l, Some(&bad), NLM_F_CREATE as u16), Err(Errno::EINVAL));
    }

    #[test]
    fn the_window_matches_as_the_fingerprint_says() {
        let ctx = |window: u16| NfOsfHdrCtx {
            df: false,
            window,
            totlen: 44,
            ttl: 64,
            saddr: [0; 4],
            opts: &[2, 4, 0x02, 0x18],
        };
        let f = |wc, val| {
            NfOsfFinger::parse(&finger((wc, val), 64, false, 44, "x", &[(OSFOPT_MSS, 4)])).unwrap()
        };
        let m = |wc, val, window| nf_osf_match_one(&f(wc, val), NF_OSF_TTL_TRUE, &ctx(window), 0);
        assert!(m(OSF_WSS_PLAIN, 0, 1234));
        assert!(m(OSF_WSS_PLAIN, 5840, 5840) && !m(OSF_WSS_PLAIN, 5840, 5841));
        // The MSS of the SYN is 536.
        assert!(m(OSF_WSS_MSS, 4, 2144) && m(OSF_WSS_MSS, 4, 5840) && !m(OSF_WSS_MSS, 4, 2145));
        assert!(m(OSF_WSS_MTU, 4, 2304) && !m(OSF_WSS_MTU, 4, 2144));
        assert!(m(OSF_WSS_MODULO, 512, 4096) && !m(OSF_WSS_MODULO, 512, 4097));
        assert!(!m(OSF_WSS_MODULO, 0, 4096) && !m(OSF_WSS_MAX, 0, 4096));
    }
}
