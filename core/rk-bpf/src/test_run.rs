//! `BPF_PROG_TEST_RUN`, net/bpf/test_run.c of Linux.
//!
//! The command runs a program once or more on a packet of the caller, and gives the result of
//! the last run. The socket filters and the `BPF_PROG_TYPE_CGROUP_SKB` programs run on a packet
//! that comes in on the loopback device, as `bpf_prog_test_run_skb` of Linux. The other program
//! types of rukernel have no test run, and give `ENOTSUPP`, as on Linux.

use crate::attr::BpfAttr;
use crate::helpers::HelperEnv;
use crate::prog::prog_type::{BPF_PROG_TYPE_CGROUP_SKB, BPF_PROG_TYPE_SOCKET_FILTER};
use crate::prog::{BpfProg, SkBuff, sk_buff};
use alloc::vec;
use alloc::vec::Vec;
use rk_abi::Errno;

type Result<T> = core::result::Result<T, Errno>;

/// The fields of `BPF_PROG_TEST_RUN`, `test`.
pub mod test {
    /// `prog_fd`.
    pub const PROG_FD: usize = 0;
    /// `retval`.
    pub const RETVAL: usize = 4;
    /// `data_size_in`.
    pub const DATA_SIZE_IN: usize = 8;
    /// `data_size_out`.
    pub const DATA_SIZE_OUT: usize = 12;
    /// `data_in`.
    pub const DATA_IN: usize = 16;
    /// `data_out`.
    pub const DATA_OUT: usize = 24;
    /// `repeat`.
    pub const REPEAT: usize = 32;
    /// `duration`.
    pub const DURATION: usize = 36;
    /// `ctx_size_in`.
    pub const CTX_SIZE_IN: usize = 40;
    /// `ctx_size_out`.
    pub const CTX_SIZE_OUT: usize = 44;
    /// `ctx_in`.
    pub const CTX_IN: usize = 48;
    /// `ctx_out`.
    pub const CTX_OUT: usize = 56;
    /// `flags`.
    pub const FLAGS: usize = 64;
    /// `cpu`.
    pub const CPU: usize = 68;
    /// `batch_size`.
    pub const BATCH_SIZE: usize = 72;
}

/// The error of a program type without a test run, `ENOTSUPP` of include/linux/errno.h.
pub const ENOTSUPP: Errno = Errno::ENOTSUPP;

/// The size of the Ethernet header, `ETH_HLEN`.
const ETH_HLEN: usize = 14;
/// The largest packet: `PAGE_SIZE` less the head room and the tail room of the buffer, as
/// `bpf_test_init` of Linux on x86_64 and arm64.
const MAX_DATA: usize = 4096 - (64 + 2) - 320;
/// `BPF_F_TEST_SKB_CHECKSUM_COMPLETE`.
const BPF_F_TEST_SKB_CHECKSUM_COMPLETE: u32 = 1 << 2;
/// The index of the loopback device, which gets the packet.
const LOOPBACK_IFINDEX: u32 = 1;
/// `GSO_LEGACY_MAX_SIZE`.
const GSO_LEGACY_MAX_SIZE: u32 = 65536;
/// `GSO_MAX_SEGS`.
const GSO_MAX_SEGS: u32 = 65535;

/// The offsets in `struct __sk_buff`, as `usize`.
mod skb {
    use crate::prog::sk_buff as o;
    pub(super) const TC_INDEX: usize = o::TC_INDEX as usize;
    pub(super) const TSTAMP: usize = o::TSTAMP as usize;
    pub(super) const WIRE_LEN: usize = o::WIRE_LEN as usize;
    pub(super) const GSO_SEGS: usize = o::GSO_SEGS as usize;
    pub(super) const SK: usize = o::SK as usize;
    pub(super) const GSO_SIZE: usize = o::GSO_SIZE as usize;
    pub(super) const TSTAMP_TYPE: usize = o::TSTAMP_TYPE as usize;
    pub(super) const HWTSTAMP: usize = o::HWTSTAMP as usize;
}

/// What the test run needs of the caller.
pub trait TestRunEnv {
    /// Copies the user memory at `addr` to `buf`. A bad address gives `EFAULT`.
    fn copy_from_user(&self, addr: u64, buf: &mut [u8]) -> Result<()>;
    /// Copies `buf` to the user memory at `addr`. A bad address gives `EFAULT`.
    fn copy_to_user(&self, addr: u64, buf: &[u8]) -> Result<()>;
    /// What the helpers see: the task of the caller.
    fn helpers(&self) -> &dyn HelperEnv;
    /// The nanoseconds after the boot.
    fn now_ns(&self) -> u64;
}

/// Runs the test run of the program type, as the `test_run` operation of Linux.
pub fn bpf_prog_test_run(
    env: &dyn TestRunEnv,
    prog: &BpfProg,
    attr: &BpfAttr,
    uattr: u64,
) -> Result<i64> {
    match prog.prog_type {
        BPF_PROG_TYPE_SOCKET_FILTER | BPF_PROG_TYPE_CGROUP_SKB => {
            bpf_prog_test_run_skb(env, prog, attr, uattr)
        }
        _ => Err(ENOTSUPP),
    }
}

/// Copies the packet of the caller, as `bpf_test_init` of Linux.
fn bpf_test_init(env: &dyn TestRunEnv, attr: &BpfAttr) -> Result<Vec<u8>> {
    let size = attr.u32(test::DATA_SIZE_IN) as usize;
    if !(ETH_HLEN..=MAX_DATA).contains(&size) {
        return Err(Errno::EINVAL);
    }
    let mut data = vec![0; size];
    env.copy_from_user(attr.u64(test::DATA_IN), &mut data)?;
    Ok(data)
}

/// Copies the context of the caller, as `bpf_ctx_init` of Linux. No context gives `None`.
fn bpf_ctx_init(env: &dyn TestRunEnv, attr: &BpfAttr, max_size: usize) -> Result<Option<Vec<u8>>> {
    let data_in = attr.u64(test::CTX_IN);
    if data_in == 0 && attr.u64(test::CTX_OUT) == 0 {
        return Ok(None);
    }
    let mut data = vec![0; max_size];
    if data_in != 0 {
        let size = attr.u32(test::CTX_SIZE_IN) as usize;
        let n = crate::attr::bpf_check_uarg_tail_zero(max_size, size, |rest| {
            env.copy_from_user(data_in + max_size as u64, rest)
        })?;
        env.copy_from_user(data_in, &mut data[..n])?;
    }
    Ok(Some(data))
}

/// Tells if the bytes of `ctx` from `from` to `to` are zero, `range_is_zero` of Linux.
fn range_is_zero(ctx: &[u8], from: usize, to: usize) -> bool {
    ctx[from..to].iter().all(|&b| b == 0)
}

fn get_u32(ctx: &[u8], off: usize) -> u32 {
    u32::from_ne_bytes([ctx[off], ctx[off + 1], ctx[off + 2], ctx[off + 3]])
}

fn get_u64(ctx: &[u8], off: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&ctx[off..off + 8]);
    u64::from_ne_bytes(b)
}

fn put_u32(ctx: &mut [u8], off: usize, v: u32) {
    ctx[off..off + 4].copy_from_slice(&v.to_ne_bytes());
}

/// The state of the packet that the context of the caller sets, and that the caller gets back.
#[derive(Default)]
struct SkbState {
    mark: u32,
    priority: u32,
    skb_iif: u32,
    cb: [u8; 20],
    tstamp: u64,
    pkt_len: u32,
    gso_segs: u32,
    gso_size: u32,
    hwtstamp: u64,
}

/// Checks the context of the caller and takes its fields, `convert___skb_to_skb` of Linux. Each
/// field that the caller cannot set must be zero.
fn skb_from_user(ctx: &[u8], len: u32, st: &mut SkbState) -> Result<()> {
    use sk_buff::{CB, CB_END, IFINDEX, MARK, PRIORITY};
    let (mark, priority, ifindex, cb) = (MARK as usize, PRIORITY as usize, IFINDEX as usize, CB);
    let zero = [
        (0, mark),
        (mark + 4, priority),
        (ifindex + 4, cb as usize),
        (CB_END as usize, skb::TSTAMP),
        (skb::GSO_SEGS + 4, skb::GSO_SIZE),
        (skb::GSO_SIZE + 4, skb::HWTSTAMP),
    ];
    if zero.iter().any(|&(from, to)| !range_is_zero(ctx, from, to)) {
        return Err(Errno::EINVAL);
    }
    const _: () = assert!(
        skb::TC_INDEX == sk_buff::IFINDEX as usize + 4
            && skb::SK < skb::GSO_SIZE
            && skb::TSTAMP_TYPE == skb::GSO_SIZE + 4
    );
    st.mark = get_u32(ctx, mark);
    st.priority = get_u32(ctx, priority);
    st.skb_iif = get_u32(ctx, sk_buff::INGRESS_IFINDEX as usize);
    st.tstamp = get_u64(ctx, skb::TSTAMP);
    st.cb.copy_from_slice(&ctx[cb as usize..CB_END as usize]);
    let wire_len = get_u32(ctx, skb::WIRE_LEN);
    st.pkt_len = if wire_len == 0 {
        len
    } else {
        if wire_len < len || wire_len > GSO_LEGACY_MAX_SIZE {
            return Err(Errno::EINVAL);
        }
        wire_len
    };
    st.gso_segs = get_u32(ctx, skb::GSO_SEGS);
    if st.gso_segs > GSO_MAX_SEGS {
        return Err(Errno::EINVAL);
    }
    st.gso_size = get_u32(ctx, skb::GSO_SIZE);
    st.hwtstamp = get_u64(ctx, skb::HWTSTAMP);
    Ok(())
}

/// Gives the caller the fields of the packet after the run, `convert_skb_to___skb` of Linux.
fn skb_to_user(st: &SkbState, ctx: &mut [u8]) {
    put_u32(ctx, sk_buff::MARK as usize, st.mark);
    put_u32(ctx, sk_buff::PRIORITY as usize, st.priority);
    put_u32(ctx, sk_buff::INGRESS_IFINDEX as usize, st.skb_iif);
    put_u32(ctx, sk_buff::IFINDEX as usize, LOOPBACK_IFINDEX);
    ctx[skb::TSTAMP..skb::TSTAMP + 8].copy_from_slice(&st.tstamp.to_ne_bytes());
    ctx[sk_buff::CB as usize..sk_buff::CB_END as usize].copy_from_slice(&st.cb);
    put_u32(ctx, skb::WIRE_LEN, st.pkt_len);
    put_u32(ctx, skb::GSO_SEGS, st.gso_segs);
    ctx[skb::HWTSTAMP..skb::HWTSTAMP + 8].copy_from_slice(&st.hwtstamp.to_ne_bytes());
}

/// The protocol and the packet type of an Ethernet frame on the loopback device, as
/// `eth_type_trans` of Linux. The protocol is in network byte order.
fn eth_type_trans(frame: &[u8]) -> (u16, u32) {
    let dest = &frame[..6];
    // The loopback device has the address 00:00:00:00:00:00.
    let pkt_type = if dest.iter().all(|&b| b == 0) {
        0 // PACKET_HOST
    } else if dest[0] & 1 != 0 {
        if dest.iter().all(|&b| b == 0xff) { 1 } else { 2 } // PACKET_BROADCAST, PACKET_MULTICAST
    } else {
        3 // PACKET_OTHERHOST
    };
    let proto = u16::from_be_bytes([frame[12], frame[13]]);
    let proto = if proto >= 0x600 {
        proto
    } else if frame.get(14..16) == Some(&[0xff, 0xff]) {
        1 // ETH_P_802_3
    } else {
        4 // ETH_P_802_2
    };
    (proto.to_be(), pkt_type)
}

/// Gives the caller the packet and the result, `bpf_test_finish` of Linux. A buffer that is too
/// small gets the start of the packet, and the call gives `ENOSPC`.
fn bpf_test_finish(
    env: &dyn TestRunEnv,
    attr: &BpfAttr,
    uattr: u64,
    data: &[u8],
    retval: u32,
    duration: u32,
) -> Result<()> {
    let size = data.len() as u32;
    let size_out = attr.u32(test::DATA_SIZE_OUT);
    let mut copy = size;
    let mut err = Ok(());
    if size_out != 0 && copy > size_out {
        copy = size_out;
        err = Err(Errno::ENOSPC);
    }
    let data_out = attr.u64(test::DATA_OUT);
    if data_out != 0 {
        env.copy_to_user(data_out, &data[..copy as usize])?;
    }
    env.copy_to_user(uattr + test::DATA_SIZE_OUT as u64, &size.to_ne_bytes())?;
    env.copy_to_user(uattr + test::RETVAL as u64, &retval.to_ne_bytes())?;
    env.copy_to_user(uattr + test::DURATION as u64, &duration.to_ne_bytes())?;
    err
}

/// Gives the caller the context after the run, `bpf_ctx_finish` of Linux.
fn bpf_ctx_finish(env: &dyn TestRunEnv, attr: &BpfAttr, uattr: u64, ctx: &[u8]) -> Result<()> {
    let data_out = attr.u64(test::CTX_OUT);
    if data_out == 0 {
        return Ok(());
    }
    let size = ctx.len() as u32;
    let size_out = attr.u32(test::CTX_SIZE_OUT);
    let (copy, err) = if size > size_out { (size_out, Err(Errno::ENOSPC)) } else { (size, Ok(())) };
    env.copy_to_user(data_out, &ctx[..copy as usize])?;
    env.copy_to_user(uattr + test::CTX_SIZE_OUT as u64, &size.to_ne_bytes())?;
    err
}

/// Runs the program `repeat` times, at least once, as `bpf_test_run` of Linux. Gives the result
/// of the last run and the mean time of a run in nanoseconds.
fn bpf_test_run(
    env: &dyn TestRunEnv,
    prog: &BpfProg,
    skb: &mut SkBuff<'_>,
    repeat: u32,
) -> (u32, u32) {
    let repeat = repeat.max(1);
    let start = env.now_ns();
    let mut retval = 0;
    for _ in 0..repeat {
        retval = prog.run(skb, env.helpers()) as u32;
    }
    let ns = env.now_ns().saturating_sub(start) / u64::from(repeat);
    (retval, ns.min(u64::from(u32::MAX)) as u32)
}

/// The test run of the programs of a packet, `bpf_prog_test_run_skb` of Linux.
fn bpf_prog_test_run_skb(
    env: &dyn TestRunEnv,
    prog: &BpfProg,
    attr: &BpfAttr,
    uattr: u64,
) -> Result<i64> {
    if attr.u32(test::FLAGS) & !BPF_F_TEST_SKB_CHECKSUM_COMPLETE != 0
        || attr.u32(test::CPU) != 0
        || attr.u32(test::BATCH_SIZE) != 0
    {
        return Err(Errno::EINVAL);
    }
    let mut data = bpf_test_init(env, attr)?;
    let mut ctx = bpf_ctx_init(env, attr, sk_buff::SIZE as usize)?;
    if let Some(c) = &ctx {
        // rukernel gives the test run only the loopback device.
        if get_u32(c, sk_buff::IFINDEX as usize) > LOOPBACK_IFINDEX {
            return Err(Errno::ENODEV);
        }
    }
    let (protocol, pkt_type) = eth_type_trans(&data);
    let net = &data[ETH_HLEN..];
    // The socket of the packet has the addresses of the packet, as the dummy socket of Linux.
    let (mut family, mut local_ip, mut remote_ip) = (0, [0u8; 16], [0u8; 16]);
    match u16::from_be(protocol) {
        0x0800 => {
            family = 2;
            if net.len() >= 20 {
                local_ip[..4].copy_from_slice(&net[12..16]);
                remote_ip[..4].copy_from_slice(&net[16..20]);
            }
        }
        0x86dd => {
            family = 10;
            if net.len() >= 40 {
                local_ip.copy_from_slice(&net[8..24]);
                remote_ip.copy_from_slice(&net[24..40]);
            }
        }
        _ => {}
    }
    let mut st = SkbState::default();
    if let Some(c) = &ctx {
        skb_from_user(c, net.len() as u32, &mut st)?;
    }
    let mut skb = SkBuff {
        data: net,
        protocol,
        pkt_type,
        mark: st.mark,
        priority: st.priority,
        ingress_ifindex: st.skb_iif,
        ifindex: LOOPBACK_IFINDEX,
        cb: st.cb,
        family,
        remote_ip,
        local_ip,
        tstamp: st.tstamp,
        gso_segs: st.gso_segs,
        gso_size: st.gso_size,
        hwtstamp: st.hwtstamp,
        ..SkBuff::default()
    };
    let (retval, duration) = bpf_test_run(env, prog, &mut skb, attr.u32(test::REPEAT));
    st.mark = skb.mark;
    st.priority = skb.priority;
    st.cb = skb.cb;
    st.tstamp = skb.tstamp;
    // The Ethernet header goes back on the packet with zero bytes.
    data[..ETH_HLEN].fill(0);
    if let Some(c) = &mut ctx {
        skb_to_user(&st, c);
    }
    bpf_test_finish(env, attr, uattr, &data, retval, duration)?;
    if let Some(c) = &ctx {
        bpf_ctx_finish(env, attr, uattr, c)?;
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::tests::NoEnv;
    use crate::insn::asm::*;
    use crate::insn::*;
    use alloc::sync::Arc;
    use core::cell::RefCell;

    /// A caller with a flat memory from address 0x1000.
    struct Mem(RefCell<Vec<u8>>);

    const BASE: u64 = 0x1000;
    const UATTR: u64 = BASE;
    const DATA: u64 = BASE + 0x200;
    const OUT: u64 = BASE + 0x400;
    const CTX: u64 = BASE + 0x800;

    impl TestRunEnv for Mem {
        fn copy_from_user(&self, addr: u64, buf: &mut [u8]) -> Result<()> {
            let at = (addr - BASE) as usize;
            let m = self.0.borrow();
            buf.copy_from_slice(m.get(at..at + buf.len()).ok_or(Errno::EFAULT)?);
            Ok(())
        }
        fn copy_to_user(&self, addr: u64, buf: &[u8]) -> Result<()> {
            let at = (addr - BASE) as usize;
            let mut m = self.0.borrow_mut();
            m.get_mut(at..at + buf.len()).ok_or(Errno::EFAULT)?.copy_from_slice(buf);
            Ok(())
        }
        fn helpers(&self) -> &dyn HelperEnv {
            &NoEnv
        }
        fn now_ns(&self) -> u64 {
            0
        }
    }

    fn prog(prog_type: u32, insns: &[BpfInsn]) -> Arc<BpfProg> {
        let mut p = crate::core::tests::prog(insns, Vec::new());
        p.prog_type = prog_type;
        Arc::new(p)
    }

    fn get(m: &Mem, addr: u64, len: usize) -> Vec<u8> {
        let mut v = vec![0; len];
        m.copy_from_user(addr, &mut v).unwrap();
        v
    }

    fn attr(size_in: u32, size_out: u32) -> BpfAttr {
        let mut a = BpfAttr::zeroed();
        a.set_u32(test::DATA_SIZE_IN, size_in);
        a.set_u64(test::DATA_IN, DATA);
        a.set_u32(test::DATA_SIZE_OUT, size_out);
        a.set_u64(test::DATA_OUT, OUT);
        a
    }

    #[test]
    fn a_socket_filter_runs_on_the_packet_after_the_ethernet_header() {
        let m = Mem(RefCell::new(vec![0; 0x1000]));
        let mut frame = vec![0u8; 64];
        frame[..6].copy_from_slice(&[0xff; 6]);
        frame[12..14].copy_from_slice(&[0x08, 0x00]);
        frame[14] = 0x45;
        m.copy_to_user(DATA, &frame).unwrap();
        // r0 = skb->len + skb->pkt_type * 1000 + the first byte of the network header.
        let p = prog(
            BPF_PROG_TYPE_SOCKET_FILTER,
            &[
                mov64_reg(6, 1),
                ldx_mem(BPF_W, 0, 6, sk_buff::LEN as i16),
                ldx_mem(BPF_W, 2, 6, sk_buff::PKT_TYPE as i16),
                alu64_imm(BPF_MUL, 2, 1000),
                alu64_reg(BPF_ADD, 0, 2),
                mov64_reg(7, 0),
                ld_abs(BPF_B, 0),
                alu64_reg(BPF_ADD, 0, 7),
                exit(),
            ],
        );
        bpf_prog_test_run(&m, &p, &attr(64, 128), UATTR).unwrap();
        let out = get(&m, UATTR, 40);
        let u = |o: usize| u32::from_ne_bytes(out[o..o + 4].try_into().unwrap());
        assert_eq!(u(test::RETVAL), 50 + 1000 + 0x45);
        assert_eq!(u(test::DATA_SIZE_OUT), 64);
        let data = get(&m, OUT, 64);
        assert_eq!(&data[..14], &[0; 14]);
        assert_eq!(&data[14..], &frame[14..]);
    }

    #[test]
    fn the_errors_of_a_test_run() {
        let m = Mem(RefCell::new(vec![0; 0x1000]));
        let p = prog(BPF_PROG_TYPE_SOCKET_FILTER, &[mov64_imm(0, 1), exit()]);
        assert_eq!(bpf_prog_test_run(&m, &p, &attr(13, 0), UATTR), Err(Errno::EINVAL));
        let mut a = attr(14, 0);
        a.set_u32(test::CPU, 1);
        assert_eq!(bpf_prog_test_run(&m, &p, &a, UATTR), Err(Errno::EINVAL));
        // A small buffer gets the start of the packet.
        assert_eq!(bpf_prog_test_run(&m, &p, &attr(20, 16), UATTR), Err(Errno::ENOSPC));
        let dev = prog(crate::prog::prog_type::BPF_PROG_TYPE_CGROUP_DEVICE, &[exit()]);
        assert_eq!(bpf_prog_test_run(&m, &dev, &attr(14, 0), UATTR), Err(ENOTSUPP));
    }

    #[test]
    fn the_context_of_a_test_run() {
        let m = Mem(RefCell::new(vec![0; 0x1000]));
        let p = prog(
            BPF_PROG_TYPE_SOCKET_FILTER,
            &[
                ldx_mem(BPF_W, 0, 1, sk_buff::MARK as i16),
                mov64_imm(2, 7),
                stx_mem(BPF_W, 1, 2, sk_buff::CB as i16),
                exit(),
            ],
        );
        let mut ctx = vec![0u8; sk_buff::SIZE as usize];
        put_u32(&mut ctx, sk_buff::MARK as usize, 42);
        m.copy_to_user(CTX, &ctx).unwrap();
        let mut a = attr(14, 0);
        a.set_u32(test::CTX_SIZE_IN, sk_buff::SIZE);
        a.set_u64(test::CTX_IN, CTX);
        a.set_u32(test::CTX_SIZE_OUT, sk_buff::SIZE);
        a.set_u64(test::CTX_OUT, CTX);
        bpf_prog_test_run(&m, &p, &a, UATTR).unwrap();
        assert_eq!(u32::from_ne_bytes(get(&m, UATTR + 4, 4).try_into().unwrap()), 42);
        let out = get(&m, CTX, sk_buff::SIZE as usize);
        assert_eq!(get_u32(&out, sk_buff::CB as usize), 7);
        assert_eq!(get_u32(&out, sk_buff::IFINDEX as usize), 1);
        // A field that the caller cannot set gives EINVAL.
        put_u32(&mut ctx, sk_buff::LEN as usize, 1);
        m.copy_to_user(CTX, &ctx).unwrap();
        assert_eq!(bpf_prog_test_run(&m, &p, &a, UATTR), Err(Errno::EINVAL));
    }
}
