//! The netfilter hooks, as net/netfilter/core.c of Linux.
//!
//! The IPv4 and IPv6 paths call `nf_hook` at five points: `NF_INET_PRE_ROUTING` when a packet
//! comes in, `NF_INET_LOCAL_IN` before the host takes it, `NF_INET_FORWARD` before the host
//! forwards it, `NF_INET_LOCAL_OUT` when the host sends it, and `NF_INET_POST_ROUTING` before it
//! goes to the link. Each network namespace has a list of hooks for each family and each hook
//! point, in the order of the priority. Each hook gives a verdict: `NF_ACCEPT` gives the packet
//! to the next hook, `NF_DROP` drops it, `NF_STOLEN` tells that the hook took it, and
//! `NF_QUEUE` gives it to a queue in user space.
//!
//! Linux uses a static key for each hook point (`nf_hooks_needed`), so that a path with no hook
//! does not read the list. Here a counter for each family and hook point does the same: when no
//! namespace has a hook at the point, `nf_hook` reads one atomic value and takes no lock.
//! When a hook exists, `nf_hook` copies a reference to the list under the lock, and the hooks
//! run without the lock, as the RCU read side of Linux.

use crate::buf::NetBuf;
use crate::ns::{self, PerNet};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use rk_abi::Errno;
use rk_frame::sync::SpinLock;
use rk_vfs::inode::Result;

pub mod nf_conntrack;
pub mod nf_nat;
pub mod nf_reject;
pub mod nf_tables_api;

/// The verdict that drops the packet.
pub const NF_DROP: u32 = 0;
/// The verdict that gives the packet to the next hook.
pub const NF_ACCEPT: u32 = 1;
/// The verdict that tells that the hook took the packet.
pub const NF_STOLEN: u32 = 2;
/// The verdict that gives the packet to a queue in user space.
pub const NF_QUEUE: u32 = 3;
/// The verdict that runs the hook again.
pub const NF_REPEAT: u32 = 4;
/// The verdict that stops the hooks, deprecated in Linux.
pub const NF_STOP: u32 = 5;
/// The largest verdict.
pub const NF_MAX_VERDICT: u32 = NF_STOP;
/// The bits of the verdict in the value that a hook gives.
pub const NF_VERDICT_MASK: u32 = 0x0000_00ff;
/// The flag of `NF_QUEUE` that accepts the packet when no program reads the queue.
pub const NF_VERDICT_FLAG_QUEUE_BYPASS: u32 = 0x0000_8000;
/// The bits of the number of the queue, or of the error of `NF_DROP`.
pub const NF_VERDICT_QMASK: u32 = 0xffff_0000;
/// The shift of the number of the queue.
pub const NF_VERDICT_QBITS: u32 = 16;

/// `NF_DROP` with the error `e` for the sender, as `NF_DROP_ERR` of Linux.
pub const fn nf_drop_err(e: Errno) -> u32 {
    ((e.get() as u32) << NF_VERDICT_QBITS) | NF_DROP
}

/// `NF_QUEUE` to the queue `n`, as `NF_QUEUE_NR` of Linux.
pub const fn nf_queue_nr(n: u16) -> u32 {
    ((n as u32) << NF_VERDICT_QBITS) | NF_QUEUE
}

/// The hook point of a packet that comes in, before the route.
pub const NF_INET_PRE_ROUTING: u8 = 0;
/// The hook point of a packet for the host.
pub const NF_INET_LOCAL_IN: u8 = 1;
/// The hook point of a packet that the host forwards.
pub const NF_INET_FORWARD: u8 = 2;
/// The hook point of a packet that the host sends.
pub const NF_INET_LOCAL_OUT: u8 = 3;
/// The hook point of a packet that goes to the link, after the route.
pub const NF_INET_POST_ROUTING: u8 = 4;
/// The count of the hook points of IPv4 and IPv6.
pub const NF_INET_NUMHOOKS: u8 = 5;
/// The hook point of the ingress of a device, for the family `NFPROTO_INET`.
pub const NF_INET_INGRESS: u8 = NF_INET_NUMHOOKS;

/// No family.
pub const NFPROTO_UNSPEC: u8 = 0;
/// IPv4 and IPv6. A hook of this family goes in the lists of both.
pub const NFPROTO_INET: u8 = 1;
/// IPv4.
pub const NFPROTO_IPV4: u8 = 2;
/// ARP.
pub const NFPROTO_ARP: u8 = 3;
/// The devices.
pub const NFPROTO_NETDEV: u8 = 5;
/// The bridges.
pub const NFPROTO_BRIDGE: u8 = 7;
/// IPv6.
pub const NFPROTO_IPV6: u8 = 10;
/// The count of the families.
pub const NFPROTO_NUMPROTO: u8 = 11;

/// The priority of the first hook.
pub const NF_IP_PRI_FIRST: i32 = i32::MIN;
/// The priority of the `raw` table.
pub const NF_IP_PRI_RAW: i32 = -300;
/// The priority of the connection tracking.
pub const NF_IP_PRI_CONNTRACK: i32 = -200;
/// The priority of the `mangle` table.
pub const NF_IP_PRI_MANGLE: i32 = -150;
/// The priority of the destination NAT.
pub const NF_IP_PRI_NAT_DST: i32 = -100;
/// The priority of the `filter` table.
pub const NF_IP_PRI_FILTER: i32 = 0;
/// The priority of the `security` table.
pub const NF_IP_PRI_SECURITY: i32 = 50;
/// The priority of the source NAT.
pub const NF_IP_PRI_NAT_SRC: i32 = 100;
/// The priority of the last hook.
pub const NF_IP_PRI_LAST: i32 = i32::MAX;

/// The most hooks in one list, `MAX_HOOK_COUNT` of Linux.
const MAX_HOOK_COUNT: usize = 1024;

/// The state of a packet at a hook, as `struct nf_hook_state` of Linux.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NfHookState {
    /// The hook point.
    pub hook: u8,
    /// The family of the packet: `NFPROTO_IPV4` or `NFPROTO_IPV6`.
    pub pf: u8,
    /// The index of the device that the packet came in on, or 0.
    pub in_dev: u32,
    /// The index of the device that the packet goes out on, or 0.
    pub out_dev: u32,
}

/// A function of a hook, as `nf_hookfn` of Linux. It gives a verdict for the packet, and it can
/// change the packet. After `NF_STOLEN` or `NF_DROP` the caller drops the packet.
pub trait NfHookFn: Send + Sync {
    /// Gives the verdict for `skb`.
    fn hook(&self, skb: &mut NetBuf, state: &NfHookState) -> u32;
}

/// A hook to register, as `struct nf_hook_ops` of Linux.
#[derive(Clone)]
pub struct NfHookOps {
    /// The function.
    pub hook: Arc<dyn NfHookFn>,
    /// The family: `NFPROTO_IPV4`, `NFPROTO_IPV6` or `NFPROTO_INET`.
    pub pf: u8,
    /// The hook point.
    pub hooknum: u8,
    /// The priority. A hook with a lower value runs first.
    pub priority: i32,
}

/// A hook in a list, as `struct nf_hook_entry` of Linux.
#[derive(Clone)]
struct NfHookEntry {
    hook: Arc<dyn NfHookFn>,
    priority: i32,
}

/// The lists of the hooks of IPv4 and IPv6 of a namespace, as `struct netns_nf` of Linux. A
/// list does not change: a new hook makes a new list, so that `nf_hook` can run a list
/// without the lock.
#[derive(Default)]
struct NetnsNf {
    hooks_ipv4: [Option<Arc<[NfHookEntry]>>; NF_INET_NUMHOOKS as usize],
    hooks_ipv6: [Option<Arc<[NfHookEntry]>>; NF_INET_NUMHOOKS as usize],
}

impl NetnsNf {
    fn list(&mut self, pf: u8, hooknum: u8) -> Option<&mut Option<Arc<[NfHookEntry]>>> {
        let at = usize::from(hooknum);
        match pf {
            NFPROTO_IPV4 => self.hooks_ipv4.get_mut(at),
            NFPROTO_IPV6 => self.hooks_ipv6.get_mut(at),
            _ => None,
        }
    }
}

static NF: PerNet<SpinLock<NetnsNf>> = PerNet::new(|| SpinLock::new(NetnsNf::default()));

/// The count of the hooks of all namespaces for each family and hook point, as
/// `nf_hooks_needed` of Linux.
static NF_HOOKS_NEEDED: [[AtomicU32; NF_INET_NUMHOOKS as usize]; 2] =
    [const { [const { AtomicU32::new(0) }; NF_INET_NUMHOOKS as usize] }; 2];

fn needed(pf: u8, hooknum: u8) -> Option<&'static AtomicU32> {
    let row = match pf {
        NFPROTO_IPV4 => 0,
        NFPROTO_IPV6 => 1,
        _ => return None,
    };
    NF_HOOKS_NEEDED[row].get(usize::from(hooknum))
}

/// Tells if a namespace has a hook of the family `pf` at `hooknum`. The paths call this to
/// skip the work that only a hook needs.
#[inline]
pub fn nf_hook_active(pf: u8, hooknum: u8) -> bool {
    needed(pf, hooknum).is_some_and(|n| n.load(Ordering::Relaxed) != 0)
}

/// The families of the lists that a hook of `pf` goes in.
fn families(pf: u8) -> &'static [u8] {
    match pf {
        NFPROTO_INET => &[NFPROTO_IPV4, NFPROTO_IPV6],
        NFPROTO_IPV4 => &[NFPROTO_IPV4],
        NFPROTO_IPV6 => &[NFPROTO_IPV6],
        _ => &[],
    }
}

/// Adds `reg` to the list of the current namespace, as `nf_register_net_hook` of Linux. The
/// hook goes after the hooks with the same or a lower priority. A hook of `NFPROTO_INET` goes in
/// the lists of IPv4 and IPv6.
///
/// # Errors
///
/// Gives `EINVAL` for a family or a hook point that is not known, `EEXIST` if the hook is in
/// the list already, and `E2BIG` if the list is full.
pub fn nf_register_net_hook(reg: &NfHookOps) -> Result<()> {
    let pfs = families(reg.pf);
    if pfs.is_empty() || reg.hooknum >= NF_INET_NUMHOOKS {
        return Err(Errno::EINVAL);
    }
    let mut nf = NF.lock();
    for &pf in pfs {
        let old = nf.list(pf, reg.hooknum).and_then(|l| l.clone());
        let old = old.as_deref().unwrap_or_default();
        if old.iter().any(|e| Arc::ptr_eq(&e.hook, &reg.hook)) {
            return Err(Errno::EEXIST);
        }
        if old.len() >= MAX_HOOK_COUNT {
            return Err(Errno::E2BIG);
        }
    }
    for &pf in pfs {
        let Some(list) = nf.list(pf, reg.hooknum) else { continue };
        let old = list.as_deref().unwrap_or_default();
        // `nf_hook_entries_grow`: the new hook goes before the first hook with a higher
        // priority.
        let at = old.iter().position(|e| reg.priority < e.priority).unwrap_or(old.len());
        let mut new: Vec<NfHookEntry> = Vec::with_capacity(old.len() + 1);
        new.extend_from_slice(&old[..at]);
        new.push(NfHookEntry { hook: reg.hook.clone(), priority: reg.priority });
        new.extend_from_slice(&old[at..]);
        *list = Some(new.into());
        if let Some(n) = needed(pf, reg.hooknum) {
            n.fetch_add(1, Ordering::Relaxed);
        }
    }
    Ok(())
}

/// Removes `reg` from the list of the current namespace, as `nf_unregister_net_hook` of Linux.
/// A hook that is not in the list does nothing.
pub fn nf_unregister_net_hook(reg: &NfHookOps) {
    if reg.hooknum >= NF_INET_NUMHOOKS {
        return;
    }
    let mut nf = NF.lock();
    for &pf in families(reg.pf) {
        let Some(list) = nf.list(pf, reg.hooknum) else { continue };
        let Some(old) = list.as_deref() else { continue };
        let Some(at) = old.iter().position(|e| Arc::ptr_eq(&e.hook, &reg.hook)) else { continue };
        let new: Vec<NfHookEntry> =
            old.iter().enumerate().filter(|&(i, _)| i != at).map(|(_, e)| e.clone()).collect();
        *list = if new.is_empty() { None } else { Some(new.into()) };
        if let Some(n) = needed(pf, reg.hooknum) {
            n.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

/// Adds each hook of `regs`, as `nf_register_net_hooks` of Linux. If one fails, the hooks that
/// went in before it are removed.
///
/// # Errors
///
/// Gives the error of the hook that fails.
pub fn nf_register_net_hooks(regs: &[NfHookOps]) -> Result<()> {
    for (i, reg) in regs.iter().enumerate() {
        if let Err(e) = nf_register_net_hook(reg) {
            nf_unregister_net_hooks(&regs[..i]);
            return Err(e);
        }
    }
    Ok(())
}

/// Removes each hook of `regs`, as `nf_unregister_net_hooks` of Linux.
pub fn nf_unregister_net_hooks(regs: &[NfHookOps]) {
    for reg in regs {
        nf_unregister_net_hook(reg);
    }
}

/// The count of the hooks of the family `pf` at `hooknum` in the current namespace.
pub fn hook_count(pf: u8, hooknum: u8) -> usize {
    NF.lock().list(pf, hooknum).and_then(|l| l.as_ref().map(|l| l.len())).unwrap_or(0)
}

/// The result of the hooks for a packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NfResult {
    /// The packet continues on its path.
    Accept,
    /// A hook took the packet. The path stops, with no error.
    Stolen,
    /// A hook dropped the packet. The sender of a local packet gets the error.
    Drop(Errno),
}

impl NfResult {
    /// The result for a path that sends: `Ok(true)` for a packet that continues, `Ok(false)` for
    /// a packet that a hook took, and the error of a drop.
    ///
    /// # Errors
    ///
    /// Gives the error of a drop.
    pub fn to_result(self) -> Result<bool> {
        match self {
            Self::Accept => Ok(true),
            Self::Stolen => Ok(false),
            Self::Drop(e) => Err(e),
        }
    }
}

/// Runs the hooks of the family `pf` at `hook` of the current namespace on `skb`, as `NF_HOOK`
/// and `nf_hook` of Linux. `in_dev` and `out_dev` are the indexes of the devices, or 0. When no
/// namespace has a hook at the point, this reads one atomic value and takes no lock.
#[inline]
pub fn nf_hook(pf: u8, hook: u8, skb: &mut NetBuf, in_dev: u32, out_dev: u32) -> NfResult {
    if !nf_hook_active(pf, hook) {
        return NfResult::Accept;
    }
    let entries = NF.lock().list(pf, hook).and_then(|l| l.clone());
    match entries {
        Some(e) => nf_hook_slow(skb, &NfHookState { hook, pf, in_dev, out_dev }, &e),
        None => NfResult::Accept,
    }
}

/// Runs the hooks `entries` on `skb` in order, as `nf_hook_slow` of Linux. There is no queue in
/// user space yet, so `NF_QUEUE` drops the packet, as `nf_queue` with no handler, or gives it
/// to the next hook if the verdict has `NF_VERDICT_FLAG_QUEUE_BYPASS`.
fn nf_hook_slow(skb: &mut NetBuf, state: &NfHookState, entries: &[NfHookEntry]) -> NfResult {
    for e in entries {
        let verdict = e.hook.hook(skb, state);
        match verdict & NF_VERDICT_MASK {
            NF_ACCEPT => {}
            NF_DROP => {
                let err = (verdict >> NF_VERDICT_QBITS) as u16;
                return NfResult::Drop(Errno::new(err).unwrap_or(Errno::EPERM));
            }
            NF_QUEUE if verdict & NF_VERDICT_FLAG_QUEUE_BYPASS != 0 => {}
            // `NF_STOLEN`, and `NF_QUEUE` with no handler, which `nf_queue` drops with no error
            // for the sender. `NF_REPEAT`, `NF_STOP` and the verdicts that are not known stop the
            // path too, as the default case of `nf_hook_slow`.
            _ => return NfResult::Stolen,
        }
    }
    NfResult::Accept
}

/// The transport header of a packet, as the fields `thoff` and `tprot` of `struct nft_pktinfo`
/// of Linux.
pub(crate) struct NfPktinfo {
    /// The offset of the transport header, or `None` for a fragment that is not the first.
    pub(crate) thoff: Option<usize>,
    /// The protocol of the transport header.
    pub(crate) l4proto: u8,
}

/// Finds the transport header of the packet `d` of the family `pf`, as `nft_set_pktinfo_ipv4`
/// and `nft_set_pktinfo_ipv6` of Linux.
pub(crate) fn nf_pktinfo(pf: u8, d: &[u8]) -> NfPktinfo {
    let none = NfPktinfo { thoff: None, l4proto: 0 };
    match pf {
        NFPROTO_IPV4 => {
            if d.len() < 20 {
                return none;
            }
            let ihl = usize::from(d[0] & 0xf) * 4;
            let frag = u16::from_be_bytes([d[6], d[7]]) & 0x1fff;
            NfPktinfo { thoff: (ihl >= 20 && frag == 0).then_some(ihl), l4proto: d[9] }
        }
        NFPROTO_IPV6 => {
            if d.len() < 40 {
                return none;
            }
            let (mut next, mut off) = (d[6], 40);
            loop {
                match next {
                    // Hop by hop, routing, destination options.
                    0 | 43 | 60 => {
                        let Some(h) = d.get(off..off + 2) else { return none };
                        next = h[0];
                        off += (usize::from(h[1]) + 1) * 8;
                    }
                    // A fragment header: a fragment that is not the first has no transport
                    // header.
                    44 => {
                        let Some(h) = d.get(off..off + 8) else { return none };
                        if u16::from_be_bytes([h[2], h[3]]) & 0xfff8 != 0 {
                            return NfPktinfo { thoff: None, l4proto: h[0] };
                        }
                        next = h[0];
                        off += 8;
                    }
                    // The authentication header counts its length in words of 4 bytes.
                    51 => {
                        let Some(h) = d.get(off..off + 2) else { return none };
                        next = h[0];
                        off += (usize::from(h[1]) + 2) * 4;
                    }
                    _ => return NfPktinfo { thoff: Some(off), l4proto: next },
                }
            }
        }
        _ => none,
    }
}

/// Removes the hooks of the current namespace that stops, so that the counters of
/// `nf_hook_active` are correct, as `netfilter_net_exit` of Linux.
fn ns_exit() {
    let mut guard = NF.lock();
    let nf = &mut *guard;
    for (pf, lists) in [(NFPROTO_IPV4, &mut nf.hooks_ipv4), (NFPROTO_IPV6, &mut nf.hooks_ipv6)] {
        for (hooknum, list) in lists.iter_mut().enumerate() {
            if let Some(l) = list.take()
                && let Some(n) = needed(pf, hooknum as u8)
            {
                n.fetch_sub(l.len() as u32, Ordering::Relaxed);
            }
        }
    }
}

/// Registers the work of netfilter for each new namespace. The stack calls this one time at
/// boot.
pub fn init() {
    ns::add_ops(|| {}, ns_exit);
    nf_conntrack::init();
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// A hook that writes its mark at the end of the packet and gives `verdict`.
    struct Mark {
        mark: u8,
        verdict: u32,
    }

    impl NfHookFn for Mark {
        fn hook(&self, skb: &mut NetBuf, _state: &NfHookState) -> u32 {
            skb.extend_from_slice(&[self.mark]);
            self.verdict
        }
    }

    fn ops(pf: u8, hooknum: u8, priority: i32, mark: u8, verdict: u32) -> NfHookOps {
        NfHookOps { hook: Arc::new(Mark { mark, verdict }), pf, hooknum, priority }
    }

    fn run(pf: u8, hook: u8) -> (NfResult, Vec<u8>) {
        let mut skb = NetBuf::new(0, 16);
        let r = nf_hook(pf, hook, &mut skb, 1, 0);
        (r, skb.data().to_vec())
    }

    // The test uses `NF_INET_FORWARD` only, so that the tests can run at the same time.
    #[test]
    fn hooks_run_in_the_order_of_the_priority() {
        let h = NF_INET_FORWARD;
        assert!(!nf_hook_active(NFPROTO_IPV4, h));
        assert_eq!(run(NFPROTO_IPV4, h), (NfResult::Accept, vec![]));
        let a = ops(NFPROTO_IPV4, h, NF_IP_PRI_FILTER, 1, NF_ACCEPT);
        let b = ops(NFPROTO_IPV4, h, NF_IP_PRI_MANGLE, 2, NF_ACCEPT);
        let c = ops(NFPROTO_IPV4, h, NF_IP_PRI_FILTER, 3, NF_ACCEPT);
        nf_register_net_hooks(&[a.clone(), b.clone(), c.clone()]).unwrap();
        assert_eq!(nf_register_net_hook(&a), Err(Errno::EEXIST));
        assert!(nf_hook_active(NFPROTO_IPV4, h));
        assert!(!nf_hook_active(NFPROTO_IPV6, h));
        assert_eq!(hook_count(NFPROTO_IPV4, h), 3);
        // The mangle hook runs first, and a hook with the same priority goes after.
        assert_eq!(run(NFPROTO_IPV4, h), (NfResult::Accept, vec![2, 1, 3]));
        // A drop stops the hooks after it, with `EPERM` or the error of the verdict.
        let d = ops(NFPROTO_IPV4, h, -1, 4, NF_DROP);
        nf_register_net_hook(&d).unwrap();
        assert_eq!(run(NFPROTO_IPV4, h), (NfResult::Drop(Errno::EPERM), vec![2, 4]));
        nf_unregister_net_hook(&d);
        let d = ops(NFPROTO_IPV4, h, -1, 4, nf_drop_err(Errno::EHOSTUNREACH));
        nf_register_net_hook(&d).unwrap();
        assert_eq!(run(NFPROTO_IPV4, h), (NfResult::Drop(Errno::EHOSTUNREACH), vec![2, 4]));
        nf_unregister_net_hook(&d);
        // A queue with no handler drops the packet without an error, unless the verdict has
        // the bypass flag.
        let q = ops(NFPROTO_IPV4, h, -1, 5, nf_queue_nr(3));
        nf_register_net_hook(&q).unwrap();
        assert_eq!(run(NFPROTO_IPV4, h), (NfResult::Stolen, vec![2, 5]));
        nf_unregister_net_hook(&q);
        let q = ops(NFPROTO_IPV4, h, -1, 5, NF_QUEUE | NF_VERDICT_FLAG_QUEUE_BYPASS);
        nf_register_net_hook(&q).unwrap();
        assert_eq!(run(NFPROTO_IPV4, h), (NfResult::Accept, vec![2, 5, 1, 3]));
        nf_unregister_net_hook(&q);
        let s = ops(NFPROTO_IPV4, h, NF_IP_PRI_LAST, 6, NF_STOLEN);
        nf_register_net_hook(&s).unwrap();
        assert_eq!(run(NFPROTO_IPV4, h), (NfResult::Stolen, vec![2, 1, 3, 6]));
        nf_unregister_net_hooks(&[a, b, c, s]);
        assert!(!nf_hook_active(NFPROTO_IPV4, h));
        assert_eq!(run(NFPROTO_IPV4, h), (NfResult::Accept, vec![]));
    }

    // The test uses `NF_INET_POST_ROUTING` only.
    #[test]
    fn inet_hooks_go_in_both_families() {
        let h = NF_INET_POST_ROUTING;
        let a = ops(NFPROTO_INET, h, 0, 1, NF_ACCEPT);
        nf_register_net_hook(&a).unwrap();
        assert_eq!(run(NFPROTO_IPV4, h), (NfResult::Accept, vec![1]));
        assert_eq!(run(NFPROTO_IPV6, h), (NfResult::Accept, vec![1]));
        assert_eq!(nf_register_net_hook(&ops(NFPROTO_ARP, h, 0, 1, 0)), Err(Errno::EINVAL));
        assert_eq!(nf_register_net_hook(&ops(NFPROTO_IPV4, 7, 0, 1, 0)), Err(Errno::EINVAL));
        nf_unregister_net_hook(&a);
        assert!(!nf_hook_active(NFPROTO_IPV4, h) && !nf_hook_active(NFPROTO_IPV6, h));
    }
}
