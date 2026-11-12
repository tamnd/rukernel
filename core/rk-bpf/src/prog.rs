//! The programs, `struct bpf_prog` of Linux, and their files.
//!
//! A program file is an anonymous inode file with the name `bpf-prog`. `/proc/PID/fdinfo` shows
//! the attributes of the program, as `bpf_prog_show_fdinfo` of Linux.

use crate::core::bpf_prog_run;
use crate::helpers::HelperEnv;
use crate::idr::Idr;
use crate::insn::{BpfInsn, INSN_SIZE};
use crate::map::BpfMap;
use crate::uapi::BPF_OBJ_NAME_LEN;
use alloc::format;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use rk_vfs::file::{File, FileOps};
use rk_vfs::inode::Metadata;

/// The program types, `enum bpf_prog_type` of Linux.
#[allow(missing_docs)]
pub mod prog_type {
    pub const BPF_PROG_TYPE_UNSPEC: u32 = 0;
    pub const BPF_PROG_TYPE_SOCKET_FILTER: u32 = 1;
    pub const BPF_PROG_TYPE_CGROUP_SKB: u32 = 8;
    pub const BPF_PROG_TYPE_CGROUP_SOCK: u32 = 9;
    pub const BPF_PROG_TYPE_CGROUP_DEVICE: u32 = 15;
    pub const BPF_PROG_TYPE_CGROUP_SOCK_ADDR: u32 = 18;
}

/// The flags of `BPF_PROG_LOAD`, `BPF_F_*` of Linux.
#[allow(missing_docs)]
pub mod prog_flags {
    pub const BPF_F_STRICT_ALIGNMENT: u32 = 1 << 0;
    pub const BPF_F_ANY_ALIGNMENT: u32 = 1 << 1;
    pub const BPF_F_TEST_RND_HI32: u32 = 1 << 2;
    pub const BPF_F_TEST_STATE_FREQ: u32 = 1 << 3;
    pub const BPF_F_SLEEPABLE: u32 = 1 << 4;
    pub const BPF_F_XDP_HAS_FRAGS: u32 = 1 << 5;
    pub const BPF_F_XDP_DEV_BOUND_ONLY: u32 = 1 << 6;
    pub const BPF_F_TEST_REG_INVARIANTS: u32 = 1 << 7;
}

/// The IDs of the programs, `prog_idr` of Linux.
pub static PROG_IDR: Idr<BpfProg> = Idr::new();

/// A program that the verifier accepted.
pub struct BpfProg {
    /// The type, `BPF_PROG_TYPE_*`.
    pub prog_type: u32,
    /// The attach type that the program expects.
    pub expected_attach_type: u32,
    /// The instructions. Each `BPF_PSEUDO_MAP_FD` load has the index of its map in `used_maps`.
    pub insns: Vec<BpfInsn>,
    /// The maps of the program, `used_maps` of Linux.
    pub used_maps: Vec<Arc<BpfMap>>,
    /// The ID.
    pub id: u32,
    /// The name.
    pub name: [u8; BPF_OBJ_NAME_LEN],
    /// The tag: the first 8 bytes of the SHA-1 of the instructions, `bpf_prog_calc_tag` of
    /// Linux.
    pub tag: [u8; 8],
    /// Tells if the license is compatible with the GPL.
    pub gpl_compatible: bool,
    /// The number of instructions that the verifier looked at.
    pub verified_insns: u32,
    /// The number of runs, `run_cnt` of `bpf_prog_stats`.
    pub run_cnt: AtomicU64,
    /// The time of the load in nanoseconds after the boot, `load_time` of Linux.
    pub load_time: u64,
    /// The real user ID of the process that loaded the program, `aux->user` of Linux.
    pub uid: u32,
    /// The program can attach only at `expected_attach_type`, `enforce_expected_attach_type`
    /// of Linux. An egress program of a cgroup that can give 2 or 3 has it.
    pub enforce_expected_attach_type: bool,
}

/// Reserves a new program ID, as `bpf_prog_alloc_id` of Linux. [`bpf_prog_publish_id`] makes the
/// ID find the program.
pub fn bpf_prog_alloc_id() -> u32 {
    PROG_IDR.alloc().unwrap_or(0)
}

/// Makes the ID of a new program find the program.
pub fn bpf_prog_publish_id(prog: &Arc<BpfProg>) {
    PROG_IDR.publish(prog.id, prog);
}

impl Drop for BpfProg {
    /// `bpf_prog_free_id` of Linux.
    fn drop(&mut self) {
        PROG_IDR.remove(self.id);
    }
}

impl BpfProg {
    /// Runs the program on `ctx`, as `bpf_prog_run` of Linux. A fault, which the verifier must
    /// stop, gives 0.
    pub fn run(&self, ctx: &mut dyn ProgCtx, env: &dyn HelperEnv) -> u64 {
        self.run_cnt.fetch_add(1, Ordering::Relaxed);
        bpf_prog_run(self, ctx, env).unwrap_or_default()
    }

    /// The memory of the program, `prog->pages * PAGE_SIZE` of Linux.
    pub fn memlock(&self) -> u64 {
        let bytes = 64 + self.insns.len() * INSN_SIZE;
        bytes.div_ceil(4096) as u64 * 4096
    }

    /// The text of `/proc/PID/fdinfo` after the common lines, as `bpf_prog_show_fdinfo` of
    /// Linux. rukernel has no JIT, so `prog_jited` is 0.
    pub fn show_fdinfo(&self) -> Vec<u8> {
        let mut tag = alloc::string::String::new();
        for b in self.tag {
            tag.push_str(&format!("{b:02x}"));
        }
        format!(
            "prog_type:\t{}\nprog_jited:\t0\nprog_tag:\t{}\nmemlock:\t{}\nprog_id:\t{}\n\
             run_time_ns:\t0\nrun_cnt:\t{}\nrecursion_misses:\t0\nverified_insns:\t{}\n",
            self.prog_type,
            tag,
            self.memlock(),
            self.id,
            self.run_cnt.load(Ordering::Relaxed),
            self.verified_insns,
        )
        .into_bytes()
    }
}

/// The tag of a program: the first 8 bytes of the SHA-1 of the instructions, with the map
/// descriptors set to zero, as `bpf_prog_calc_tag` of Linux.
pub fn bpf_prog_calc_tag(insns: &[BpfInsn]) -> [u8; 8] {
    use crate::insn::{BPF_PSEUDO_MAP_FD, BPF_PSEUDO_MAP_VALUE};
    let mut bytes = Vec::with_capacity(insns.len() * INSN_SIZE);
    let mut was_ld_map = false;
    for insn in insns {
        let mut i = *insn;
        if was_ld_map {
            i.imm = 0;
            was_ld_map = false;
        } else if i.is_ld_imm64() && matches!(i.src_reg, BPF_PSEUDO_MAP_FD | BPF_PSEUDO_MAP_VALUE) {
            i.imm = 0;
            was_ld_map = true;
        }
        bytes.extend_from_slice(&i.to_bytes());
    }
    let digest = sha1(&bytes);
    let mut tag = [0u8; 8];
    tag.copy_from_slice(&digest[..8]);
    tag
}

/// The SHA-1 of `data`, FIPS 180-4.
fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476, 0xc3d2_e1f0];
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&((data.len() as u64) * 8).to_be_bytes());
    for block in msg.as_chunks::<64>().0 {
        let mut w = [0u32; 80];
        for (i, word) in block.as_chunks::<4>().0.iter().enumerate() {
            w[i] = u32::from_be_bytes(*word);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = h;
        for (i, wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..20 => ((b & c) | (!b & d), 0x5a82_7999),
                20..40 => (b ^ c ^ d, 0x6ed9_eba1),
                40..60 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
                _ => (b ^ c ^ d, 0xca62_c1d6),
            };
            let t =
                a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(*wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }
        for (x, y) in h.iter_mut().zip([a, b, c, d, e]) {
            *x = x.wrapping_add(y);
        }
    }
    let mut out = [0u8; 20];
    for (i, x) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&x.to_be_bytes());
    }
    out
}

/// The context of a run: the memory that R1 points to at the start.
pub trait ProgCtx {
    /// Reads `size` bytes at `off`. The verifier checked the access.
    fn load(&self, off: u32, size: u32) -> Option<u64>;
    /// Writes the low `size` bytes of `value` at `off`. The verifier checked the access.
    fn store(&mut self, off: u32, size: u32, value: u64) -> Option<()>;
    /// The data of the packet, for `bpf_skb_load_bytes` and `BPF_LD_[ABS|IND]`.
    fn skb_data(&self) -> Option<&[u8]> {
        None
    }
}

/// The `struct __sk_buff` of a socket filter, as the fields that `bpf_convert_ctx_access` of
/// Linux reads from the `struct sk_buff`.
#[derive(Debug, Default)]
pub struct SkBuff<'a> {
    /// The packet.
    pub data: &'a [u8],
    /// `skb->protocol`, in network byte order.
    pub protocol: u16,
    /// `skb->pkt_type`.
    pub pkt_type: u32,
    /// `skb->mark`.
    pub mark: u32,
    /// `skb->priority`.
    pub priority: u32,
    /// The index of the device that the packet came in on.
    pub ingress_ifindex: u32,
    /// The index of the device of the packet.
    pub ifindex: u32,
    /// `skb->hash`.
    pub hash: u32,
    /// The control buffer `cb[0]` to `cb[4]`.
    pub cb: [u8; 20],
    /// The family of the socket, for a program of a cgroup.
    pub family: u32,
    /// The remote address of the socket, in network byte order. An IPv4 address is in the first
    /// 4 bytes.
    pub remote_ip: [u8; 16],
    /// The local address of the socket, as `remote_ip`.
    pub local_ip: [u8; 16],
    /// The remote port, in network byte order in the low 16 bits.
    pub remote_port: u32,
    /// The local port, in host byte order.
    pub local_port: u32,
    /// `skb->tstamp`, the time of the packet in nanoseconds.
    pub tstamp: u64,
    /// `gso_segs` of the shared info of the packet.
    pub gso_segs: u32,
    /// `gso_size` of the shared info of the packet.
    pub gso_size: u32,
    /// The time stamp of the hardware, in nanoseconds.
    pub hwtstamp: u64,
}

/// The offsets in `struct bpf_sock`, the context of `BPF_PROG_TYPE_CGROUP_SOCK`.
#[allow(missing_docs)]
pub mod bpf_sock {
    pub const BOUND_DEV_IF: u32 = 0;
    pub const FAMILY: u32 = 4;
    pub const TYPE: u32 = 8;
    pub const PROTOCOL: u32 = 12;
    pub const MARK: u32 = 16;
    pub const PRIORITY: u32 = 20;
    pub const SRC_IP4: u32 = 24;
    pub const SRC_IP6: u32 = 28;
    pub const SRC_PORT: u32 = 44;
    pub const DST_PORT: u32 = 48;
    pub const DST_IP4: u32 = 52;
    pub const DST_IP6: u32 = 56;
    pub const STATE: u32 = 72;
    pub const RX_QUEUE_MAPPING: u32 = 76;
    /// `sizeof(struct bpf_sock)`.
    pub const SIZE: u32 = 80;
}

/// The `struct bpf_sock` of a socket, as the fields that `bpf_sock_convert_ctx_access` of
/// Linux reads. The addresses and `dst_port` are in network byte order, and `src_port` is in
/// host byte order.
#[derive(Debug, Default)]
pub struct BpfSock {
    /// `sk_bound_dev_if`.
    pub bound_dev_if: u32,
    /// `sk_family`.
    pub family: u32,
    /// `sk_type`.
    pub sock_type: u32,
    /// `sk_protocol`.
    pub protocol: u32,
    /// `sk_mark`.
    pub mark: u32,
    /// `sk_priority`.
    pub priority: u32,
    /// The local address. An IPv4 address is in the first 4 bytes.
    pub src_ip: [u8; 16],
    /// The local port.
    pub src_port: u32,
    /// The remote port, as the bytes in network byte order read in the order of the machine.
    pub dst_port: u16,
    /// The remote address.
    pub dst_ip: [u8; 16],
    /// `sk_state`.
    pub state: u32,
}

impl ProgCtx for BpfSock {
    fn load(&self, off: u32, size: u32) -> Option<u64> {
        use bpf_sock::*;
        let word = |b: &[u8; 16], at: u32| {
            u32::from_ne_bytes(b[at as usize..at as usize + 4].try_into().unwrap())
        };
        let field = off & !3;
        let v: u32 = match field {
            BOUND_DEV_IF => self.bound_dev_if,
            FAMILY => self.family,
            TYPE => self.sock_type,
            PROTOCOL => self.protocol,
            MARK => self.mark,
            PRIORITY => self.priority,
            SRC_IP4 => word(&self.src_ip, 0),
            f if (SRC_IP6..SRC_PORT).contains(&f) => word(&self.src_ip, f - SRC_IP6),
            SRC_PORT => self.src_port,
            DST_PORT => u32::from(self.dst_port),
            DST_IP4 => word(&self.dst_ip, 0),
            f if (DST_IP6..STATE).contains(&f) => word(&self.dst_ip, f - DST_IP6),
            STATE => self.state,
            // rukernel has no receive queues, as a socket without one in Linux.
            RX_QUEUE_MAPPING => u32::MAX,
            _ => return None,
        };
        let v = u64::from(v >> ((off - field) * 8));
        Some(if size >= 4 { v } else { v & ((1u64 << (size * 8)) - 1) })
    }

    fn store(&mut self, off: u32, _size: u32, value: u64) -> Option<()> {
        use bpf_sock::*;
        let value = value as u32;
        match off {
            BOUND_DEV_IF => self.bound_dev_if = value,
            MARK => self.mark = value,
            PRIORITY => self.priority = value,
            _ => return None,
        }
        Some(())
    }
}

/// The offsets in `struct bpf_sock_addr`, the context of `BPF_PROG_TYPE_CGROUP_SOCK_ADDR`.
#[allow(missing_docs)]
pub mod bpf_sock_addr {
    pub const USER_FAMILY: u32 = 0;
    pub const USER_IP4: u32 = 4;
    pub const USER_IP6: u32 = 8;
    pub const USER_PORT: u32 = 24;
    pub const FAMILY: u32 = 28;
    pub const TYPE: u32 = 32;
    pub const PROTOCOL: u32 = 36;
    pub const MSG_SRC_IP4: u32 = 40;
    pub const MSG_SRC_IP6: u32 = 44;
    pub const SK: u32 = 64;
    /// `sizeof(struct bpf_sock_addr)`.
    pub const SIZE: u32 = 72;
}

/// The `struct bpf_sock_addr` of a call of `bind` or `connect`, as the `struct
/// bpf_sock_addr_kern` that `sock_addr_convert_ctx_access` of Linux reads. A program can change
/// the address and the port, and the system call then uses them. The addresses and the port are
/// in network byte order.
#[derive(Debug, Default)]
pub struct BpfSockAddr {
    /// The family of the address that the user gave.
    pub user_family: u32,
    /// The address that the user gave. An IPv4 address is in the first 4 bytes.
    pub user_ip: [u8; 16],
    /// The port that the user gave, as the bytes in network byte order read in the order of
    /// the machine.
    pub user_port: u32,
    /// `sk_family`.
    pub family: u32,
    /// `sk_type`.
    pub sock_type: u32,
    /// `sk_protocol`.
    pub protocol: u32,
    /// The source address of `sendmsg`. An IPv4 address is in the first 4 bytes.
    pub msg_src_ip: [u8; 16],
}

impl ProgCtx for BpfSockAddr {
    fn load(&self, off: u32, size: u32) -> Option<u64> {
        use bpf_sock_addr::*;
        let word = |b: &[u8; 16], at: u32| {
            u32::from_ne_bytes(b[at as usize..at as usize + 4].try_into().unwrap())
        };
        // A read of 8 bytes of an IPv6 address, as `bpf_ctx_wide_access_ok` of Linux.
        if size == 8 {
            let (b, at) = match off {
                f if (USER_IP6..USER_PORT).contains(&f) => (&self.user_ip, f - USER_IP6),
                f if (MSG_SRC_IP6..SK).contains(&f) => (&self.msg_src_ip, f - MSG_SRC_IP6),
                _ => return None,
            };
            return Some(u64::from(word(b, at)) | u64::from(word(b, at + 4)) << 32);
        }
        let field = off & !3;
        let v: u32 = match field {
            USER_FAMILY => self.user_family,
            USER_IP4 => word(&self.user_ip, 0),
            f if (USER_IP6..USER_PORT).contains(&f) => word(&self.user_ip, f - USER_IP6),
            USER_PORT => self.user_port,
            FAMILY => self.family,
            TYPE => self.sock_type,
            PROTOCOL => self.protocol,
            MSG_SRC_IP4 => word(&self.msg_src_ip, 0),
            f if (MSG_SRC_IP6..SK).contains(&f) => word(&self.msg_src_ip, f - MSG_SRC_IP6),
            _ => return None,
        };
        let v = u64::from(v >> ((off - field) * 8));
        Some(if size >= 4 { v } else { v & ((1u64 << (size * 8)) - 1) })
    }

    fn store(&mut self, off: u32, size: u32, value: u64) -> Option<()> {
        use bpf_sock_addr::*;
        let put = |b: &mut [u8; 16], at: u32, v: u32| {
            b[at as usize..at as usize + 4].copy_from_slice(&v.to_ne_bytes());
        };
        let words: &[u32] =
            if size == 8 { &[value as u32, (value >> 32) as u32] } else { &[value as u32] };
        for (i, &v) in words.iter().enumerate() {
            match off + i as u32 * 4 {
                USER_IP4 => put(&mut self.user_ip, 0, v),
                f if (USER_IP6..USER_PORT).contains(&f) => put(&mut self.user_ip, f - USER_IP6, v),
                USER_PORT => self.user_port = v,
                MSG_SRC_IP4 => put(&mut self.msg_src_ip, 0, v),
                f if (MSG_SRC_IP6..SK).contains(&f) => {
                    put(&mut self.msg_src_ip, f - MSG_SRC_IP6, v);
                }
                _ => return None,
            }
        }
        Some(())
    }
}

/// The offsets in `struct bpf_cgroup_dev_ctx`, the context of `BPF_PROG_TYPE_CGROUP_DEVICE`.
#[allow(missing_docs)]
pub mod bpf_cgroup_dev_ctx {
    pub const ACCESS_TYPE: u32 = 0;
    pub const MAJOR: u32 = 4;
    pub const MINOR: u32 = 8;
    /// `sizeof(struct bpf_cgroup_dev_ctx)`.
    pub const SIZE: u32 = 12;
}

/// The types of a device, `BPF_DEVCG_DEV_*` of Linux.
pub const BPF_DEVCG_DEV_BLOCK: u32 = 1 << 0;
/// A character device.
pub const BPF_DEVCG_DEV_CHAR: u32 = 1 << 1;
/// The accesses to a device, `BPF_DEVCG_ACC_*` of Linux: `mknod`.
pub const BPF_DEVCG_ACC_MKNOD: u32 = 1 << 0;
/// A read.
pub const BPF_DEVCG_ACC_READ: u32 = 1 << 1;
/// A write.
pub const BPF_DEVCG_ACC_WRITE: u32 = 1 << 2;

/// The context of a device program, `struct bpf_cgroup_dev_ctx` of Linux.
#[derive(Debug, Default)]
pub struct BpfCgroupDevCtx {
    /// The access in the high 16 bits and the type of the device in the low 16 bits.
    pub access_type: u32,
    /// The major number.
    pub major: u32,
    /// The minor number.
    pub minor: u32,
}

impl ProgCtx for BpfCgroupDevCtx {
    fn load(&self, off: u32, size: u32) -> Option<u64> {
        use bpf_cgroup_dev_ctx::*;
        let field = off & !3;
        let v = match field {
            ACCESS_TYPE => self.access_type,
            MAJOR => self.major,
            MINOR => self.minor,
            _ => return None,
        };
        let v = u64::from(v >> ((off - field) * 8));
        Some(if size >= 4 { v } else { v & ((1u64 << (size * 8)) - 1) })
    }

    fn store(&mut self, _off: u32, _size: u32, _value: u64) -> Option<()> {
        None
    }
}

/// The offsets in `struct __sk_buff`. Each name is the field of Linux in capitals.
#[allow(missing_docs)]
pub mod sk_buff {
    pub const LEN: u32 = 0;
    pub const PKT_TYPE: u32 = 4;
    pub const MARK: u32 = 8;
    pub const QUEUE_MAPPING: u32 = 12;
    pub const PROTOCOL: u32 = 16;
    pub const VLAN_PRESENT: u32 = 20;
    pub const VLAN_TCI: u32 = 24;
    pub const VLAN_PROTO: u32 = 28;
    pub const PRIORITY: u32 = 32;
    pub const INGRESS_IFINDEX: u32 = 36;
    pub const IFINDEX: u32 = 40;
    pub const TC_INDEX: u32 = 44;
    pub const CB: u32 = 48;
    pub const CB_END: u32 = 68;
    pub const HASH: u32 = 68;
    pub const TC_CLASSID: u32 = 72;
    pub const DATA: u32 = 76;
    pub const DATA_END: u32 = 80;
    pub const NAPI_ID: u32 = 84;
    pub const FAMILY: u32 = 88;
    pub const REMOTE_IP4: u32 = 92;
    pub const LOCAL_IP4: u32 = 96;
    pub const REMOTE_IP6: u32 = 100;
    pub const LOCAL_IP6: u32 = 116;
    pub const REMOTE_PORT: u32 = 132;
    pub const LOCAL_PORT: u32 = 136;
    pub const DATA_META: u32 = 140;
    pub const FLOW_KEYS: u32 = 144;
    pub const TSTAMP: u32 = 152;
    pub const WIRE_LEN: u32 = 160;
    pub const GSO_SEGS: u32 = 164;
    pub const SK: u32 = 168;
    pub const GSO_SIZE: u32 = 176;
    pub const TSTAMP_TYPE: u32 = 180;
    pub const HWTSTAMP: u32 = 184;
    /// `sizeof(struct __sk_buff)`.
    pub const SIZE: u32 = 192;
}

impl ProgCtx for SkBuff<'_> {
    fn load(&self, off: u32, size: u32) -> Option<u64> {
        use sk_buff::*;
        if (CB..CB_END).contains(&off) {
            let at = (off - CB) as usize;
            let b = self.cb.get(at..at + size as usize)?;
            let mut v = [0u8; 8];
            v[..b.len()].copy_from_slice(b);
            return Some(u64::from_le_bytes(v));
        }
        match off {
            TSTAMP => return Some(self.tstamp),
            HWTSTAMP => return Some(self.hwtstamp),
            _ => {}
        }
        // A narrow load reads the low bytes of the 32-bit field, as `bpf_ctx_narrow_access_ok`.
        let field = off & !3;
        let v: u32 = match field {
            LEN => self.data.len() as u32,
            PKT_TYPE => self.pkt_type,
            MARK => self.mark,
            PROTOCOL => u32::from(self.protocol),
            PRIORITY => self.priority,
            INGRESS_IFINDEX => self.ingress_ifindex,
            IFINDEX => self.ifindex,
            HASH => self.hash,
            FAMILY => self.family,
            REMOTE_PORT => self.remote_port,
            LOCAL_PORT => self.local_port,
            REMOTE_IP4 => u32::from_ne_bytes(self.remote_ip[..4].try_into().ok()?),
            LOCAL_IP4 => u32::from_ne_bytes(self.local_ip[..4].try_into().ok()?),
            f if (REMOTE_IP6..LOCAL_IP6).contains(&f) => {
                let at = (f - REMOTE_IP6) as usize;
                u32::from_ne_bytes(self.remote_ip[at..at + 4].try_into().ok()?)
            }
            f if (LOCAL_IP6..REMOTE_PORT).contains(&f) => {
                let at = (f - LOCAL_IP6) as usize;
                u32::from_ne_bytes(self.local_ip[at..at + 4].try_into().ok()?)
            }
            GSO_SEGS => self.gso_segs,
            GSO_SIZE => self.gso_size,
            QUEUE_MAPPING | VLAN_PRESENT | VLAN_TCI | VLAN_PROTO | TC_INDEX | NAPI_ID => 0,
            _ => return None,
        };
        let shift = (off - field) * 8;
        let v = u64::from(v >> shift);
        Some(if size >= 4 { v } else { v & ((1u64 << (size * 8)) - 1) })
    }

    fn store(&mut self, off: u32, size: u32, value: u64) -> Option<()> {
        use sk_buff::*;
        match off {
            MARK => self.mark = value as u32,
            PRIORITY => self.priority = value as u32,
            TSTAMP => self.tstamp = value,
            _ if (CB..CB_END).contains(&off) => {}
            _ => return None,
        }
        if !(CB..CB_END).contains(&off) {
            return Some(());
        }
        let at = (off - CB) as usize;
        let b = self.cb.get_mut(at..at + size as usize)?;
        b.copy_from_slice(&value.to_le_bytes()[..size as usize]);
        Some(())
    }

    fn skb_data(&self) -> Option<&[u8]> {
        Some(self.data)
    }
}

/// Runs a socket filter on a packet, as `bpf_prog_run_save_cb` in `sk_filter_trim_cap` of
/// Linux. The result is the number of bytes to keep: 0 drops the packet.
pub fn run_socket_filter(prog: &BpfProg, data: &[u8], protocol: u16, env: &dyn HelperEnv) -> u32 {
    let mut skb = SkBuff { data, protocol, ..SkBuff::default() };
    prog.run(&mut skb, env) as u32
}

/// The operations of a program file, `bpf_prog_fops` of Linux.
pub struct BpfProgFile {
    /// The program.
    pub prog: Arc<BpfProg>,
}

impl FileOps for BpfProgFile {
    fn metadata(&self) -> Option<Metadata> {
        Some(crate::file::anon_inode_metadata())
    }

    fn as_any(&self) -> Option<&dyn core::any::Any> {
        Some(self)
    }

    fn fdinfo(&self, _file: &File) -> Vec<u8> {
        self.prog.show_fdinfo()
    }
}

/// The program of a file, `____bpf_prog_get` of Linux. A file that is not a program gives
/// `None`.
pub fn bpf_prog_of(file: &File) -> Option<Arc<BpfProg>> {
    file.ops().as_any()?.downcast_ref::<BpfProgFile>().map(|f| f.prog.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha1_of_known_strings() {
        let hex =
            |d: [u8; 20]| d.iter().map(|b| format!("{b:02x}")).collect::<alloc::string::String>();
        assert_eq!(hex(sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(hex(sha1(b"abc")), "a9993e364706816aba3e25717850c26c9cd0d89d");
    }

    #[test]
    fn a_socket_filter_reads_the_context() {
        let skb = SkBuff { data: &[1, 2, 3], protocol: 0x0800, ..SkBuff::default() };
        assert_eq!(skb.load(sk_buff::LEN, 4), Some(3));
        assert_eq!(skb.load(sk_buff::PROTOCOL, 2), Some(0x0800));
    }

    #[test]
    fn sock_addr_ctx() {
        use bpf_sock_addr::*;
        let mut ctx = BpfSockAddr { user_port: 0x5000, ..BpfSockAddr::default() };
        assert_eq!(ctx.load(USER_PORT, 4), Some(0x5000));
        ctx.store(USER_PORT, 4, 0x5911).unwrap();
        assert_eq!(ctx.user_port, 0x5911);
        ctx.store(USER_IP6, 8, 0x0403_0201_0000_0000).unwrap();
        assert_eq!(&ctx.user_ip[..8], &[0, 0, 0, 0, 1, 2, 3, 4]);
        assert_eq!(ctx.load(USER_IP6 + 4, 4), Some(0x0403_0201));
        assert_eq!(ctx.load(USER_IP6, 8), Some(0x0403_0201_0000_0000));
        assert!(ctx.store(FAMILY, 4, 1).is_none());
    }
}
