//! Socket filters of classic BPF: `SO_ATTACH_FILTER`, as net/core/filter.c of Linux has them.
//!
//! A filter is a program of classic BPF that gets a packet and gives the number of bytes of the
//! packet that the socket keeps. The value 0 drops the packet. The check accepts the
//! instructions that `bpf_check_classic` of Linux accepts, and the interpreter runs them as Linux
//! runs the converted program. The jumps go forward only, thus each program ends.

use alloc::vec::Vec;
use rk_abi::Errno;
use rk_vfs::inode::Result;

/// The most instructions in one program, `BPF_MAXINSNS` of Linux.
pub const BPF_MAXINSNS: usize = 4096;

/// The size of one instruction, `struct sock_filter` of Linux.
pub const INSN_SIZE: usize = 8;

/// The number of 32-bit words of the scratch memory, `BPF_MEMWORDS` of Linux.
const BPF_MEMWORDS: u32 = 16;

/// The instruction classes.
const BPF_LD: u16 = 0x00;
const BPF_LDX: u16 = 0x01;
const BPF_ST: u16 = 0x02;
const BPF_STX: u16 = 0x03;
const BPF_ALU: u16 = 0x04;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;
const BPF_MISC: u16 = 0x07;

/// The size of a load.
const BPF_W: u16 = 0x00;
const BPF_H: u16 = 0x08;
const BPF_B: u16 = 0x10;

/// The mode of a load.
const BPF_ABS: u16 = 0x20;
const BPF_IND: u16 = 0x40;
const BPF_MEM: u16 = 0x60;
const BPF_LEN: u16 = 0x80;
const BPF_MSH: u16 = 0xa0;

/// The operations of the ALU and of the jumps.
const BPF_ADD: u16 = 0x00;
const BPF_SUB: u16 = 0x10;
const BPF_MUL: u16 = 0x20;
const BPF_DIV: u16 = 0x30;
const BPF_OR: u16 = 0x40;
const BPF_AND: u16 = 0x50;
const BPF_LSH: u16 = 0x60;
const BPF_RSH: u16 = 0x70;
const BPF_NEG: u16 = 0x80;
const BPF_MOD: u16 = 0x90;
const BPF_XOR: u16 = 0xa0;
const BPF_JA: u16 = 0x00;
const BPF_JEQ: u16 = 0x10;
const BPF_JGT: u16 = 0x20;
const BPF_JGE: u16 = 0x30;
const BPF_JSET: u16 = 0x40;

/// The source of the operand: the constant `k` or the register X.
const BPF_X: u16 = 0x08;
/// The value of a return: `k` or the register A.
const BPF_A: u16 = 0x10;

/// The operations of `BPF_MISC`.
const BPF_TAX: u16 = 0x00;
const BPF_TXA: u16 = 0x80;

/// The offsets of a load that are not in the packet, from <linux/filter.h>. A load at
/// `SKF_AD_OFF` and more gets data of the packet that is not in its bytes. A load at
/// `SKF_NET_OFF` or `SKF_LL_OFF` and more is relative to the network or the link header.
const SKF_AD_OFF: u32 = (-0x1000i32) as u32;
const SKF_NET_OFF: i32 = -0x10_0000;
const SKF_LL_OFF: i32 = -0x20_0000;

/// The data that a load at `SKF_AD_OFF` gets, `SKF_AD_*` of <linux/filter.h>.
const SKF_AD_PROTOCOL: u32 = 0;
const SKF_AD_PKTTYPE: u32 = 4;
const SKF_AD_IFINDEX: u32 = 8;
const SKF_AD_NLATTR: u32 = 12;
const SKF_AD_NLATTR_NEST: u32 = 16;
const SKF_AD_MARK: u32 = 20;
const SKF_AD_QUEUE: u32 = 24;
const SKF_AD_HATYPE: u32 = 28;
const SKF_AD_RXHASH: u32 = 32;
const SKF_AD_CPU: u32 = 36;
const SKF_AD_ALU_XOR_X: u32 = 40;
const SKF_AD_VLAN_TAG: u32 = 44;
const SKF_AD_VLAN_TAG_PRESENT: u32 = 48;
const SKF_AD_PAY_OFFSET: u32 = 52;
const SKF_AD_RANDOM: u32 = 56;
const SKF_AD_VLAN_TPID: u32 = 60;
const SKF_AD_MAX: u32 = 64;

/// One instruction: `struct sock_filter` of Linux.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Insn {
    /// The operation.
    pub code: u16,
    /// The offset of the jump if the condition is true.
    pub jt: u8,
    /// The offset of the jump if the condition is false.
    pub jf: u8,
    /// The constant operand.
    pub k: u32,
}

impl Insn {
    /// Reads an instruction from its 8 bytes in user memory.
    fn from_bytes(b: &[u8; INSN_SIZE]) -> Self {
        Self {
            code: u16::from_ne_bytes([b[0], b[1]]),
            jt: b[2],
            jf: b[3],
            k: u32::from_ne_bytes([b[4], b[5], b[6], b[7]]),
        }
    }

    /// Gives the 8 bytes of the instruction.
    pub fn to_bytes(self) -> [u8; INSN_SIZE] {
        let mut b = [0u8; INSN_SIZE];
        b[0..2].copy_from_slice(&self.code.to_ne_bytes());
        b[2] = self.jt;
        b[3] = self.jf;
        b[4..8].copy_from_slice(&self.k.to_ne_bytes());
        b
    }
}

/// Tells if `code` is an instruction of a socket filter, as the table `codes` of
/// `bpf_check_classic` of Linux.
fn allowed(code: u16) -> bool {
    const ALU_OPS: [u16; 10] =
        [BPF_ADD, BPF_SUB, BPF_MUL, BPF_DIV, BPF_MOD, BPF_AND, BPF_OR, BPF_XOR, BPF_LSH, BPF_RSH];
    const JMP_OPS: [u16; 4] = [BPF_JEQ, BPF_JGE, BPF_JGT, BPF_JSET];
    if code & 0x07 == BPF_ALU && code & !(0xf0 | BPF_X) == BPF_ALU {
        return ALU_OPS.contains(&(code & 0xf0)) || code == BPF_ALU | BPF_NEG;
    }
    if code & 0x07 == BPF_JMP && code & !(0xf0 | BPF_X) == BPF_JMP {
        return JMP_OPS.contains(&(code & 0xf0)) || code == BPF_JMP | BPF_JA;
    }
    matches!(
        code,
        0x20 | 0x28 | 0x30 // BPF_LD | BPF_W, BPF_H or BPF_B | BPF_ABS
            | 0x40 | 0x48 | 0x50 // BPF_LD | BPF_W, BPF_H or BPF_B | BPF_IND
            | 0x80 // BPF_LD | BPF_W | BPF_LEN
            | 0x00 // BPF_LD | BPF_IMM
            | 0x60 // BPF_LD | BPF_MEM
            | 0x81 // BPF_LDX | BPF_W | BPF_LEN
            | 0xb1 // BPF_LDX | BPF_B | BPF_MSH
            | 0x01 // BPF_LDX | BPF_IMM
            | 0x61 // BPF_LDX | BPF_MEM
            | 0x02 // BPF_ST
            | 0x03 // BPF_STX
            | 0x06 // BPF_RET | BPF_K
            | 0x16 // BPF_RET | BPF_A
            | 0x07 // BPF_MISC | BPF_TAX
            | 0x87 // BPF_MISC | BPF_TXA
    )
}

/// A program that `Filter::new` checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Filter {
    prog: Vec<Insn>,
}

/// The packet that a filter gets. A load at offset 0 gets the first byte of `frame[data..]`.
pub struct Skb<'a> {
    /// The frame with its link header.
    pub frame: &'a [u8],
    /// The offset of the link header in `frame`.
    pub mac: usize,
    /// The offset of the network header in `frame`.
    pub net: usize,
    /// The offset of the data of the socket in `frame`.
    pub data: usize,
    /// The protocol of the frame in host byte order, `skb->protocol` of Linux.
    pub protocol: u16,
    /// The type of the packet, `PACKET_HOST` and so on.
    pub pkttype: u8,
    /// The index of the device.
    pub ifindex: u32,
    /// The type of the device, `ARPHRD_ETHER` and so on.
    pub hatype: u16,
}

impl Filter {
    /// Reads a program from its instructions in `bytes` and checks it, as `bpf_prog_create_from_user`
    /// and `bpf_check_classic` of Linux do. Each jump must stay in the program, the scratch memory
    /// has 16 words, a division by a constant 0 and a shift of 32 or more are not valid, a load at
    /// `SKF_AD_OFF` must get a known datum, and the last instruction must be a return.
    ///
    /// # Errors
    ///
    /// Gives `EINVAL` if the program is empty, too long or not valid.
    pub fn new(bytes: &[u8]) -> Result<Self> {
        let (chunks, rest) = bytes.as_chunks::<INSN_SIZE>();
        let len = chunks.len();
        if !rest.is_empty() || len == 0 || len > BPF_MAXINSNS {
            return Err(Errno::EINVAL);
        }
        let prog: Vec<Insn> = chunks.iter().map(Insn::from_bytes).collect();
        for (pc, insn) in prog.iter().enumerate() {
            let (code, k) = (insn.code, insn.k);
            if !allowed(code) {
                return Err(Errno::EINVAL);
            }
            let rest = len - pc - 1;
            let ok = match code & 0x07 {
                BPF_ALU if code & BPF_X == 0 => match code & 0xf0 {
                    BPF_DIV | BPF_MOD => k != 0,
                    BPF_LSH | BPF_RSH => k < 32,
                    _ => true,
                },
                BPF_LD | BPF_LDX if code & 0xe0 == BPF_MEM => k < BPF_MEMWORDS,
                BPF_ST | BPF_STX => k < BPF_MEMWORDS,
                BPF_LD if code & 0xe0 == BPF_ABS => {
                    k < SKF_AD_OFF || (k - SKF_AD_OFF < SKF_AD_MAX && k % 4 == 0)
                }
                BPF_JMP if code & 0xf0 == BPF_JA => (k as usize) < rest,
                BPF_JMP => usize::from(insn.jt) < rest && usize::from(insn.jf) < rest,
                _ => true,
            };
            if !ok {
                return Err(Errno::EINVAL);
            }
        }
        match prog[len - 1].code {
            0x06 | 0x16 => Ok(Self { prog }),
            _ => Err(Errno::EINVAL),
        }
    }

    /// The number of instructions.
    pub fn len(&self) -> usize {
        self.prog.len()
    }

    /// Tells if the program has no instructions. A checked program has at least one.
    pub fn is_empty(&self) -> bool {
        self.prog.is_empty()
    }

    /// Runs the program on a packet and gives its return value. A load out of the packet and a
    /// division by 0 in X end the program with 0, as in Linux.
    pub fn run(&self, skb: &Skb<'_>) -> u32 {
        let mut a: u32 = 0;
        let mut x: u32 = 0;
        let mut mem = [0u32; BPF_MEMWORDS as usize];
        let mut pc = 0;
        while let Some(insn) = self.prog.get(pc) {
            pc += 1;
            let (code, k) = (insn.code, insn.k);
            match code & 0x07 {
                BPF_LD => {
                    a = match code & 0xe0 {
                        BPF_ABS if k >= SKF_AD_OFF => match ancillary(skb, k - SKF_AD_OFF, a, x) {
                            Some(v) => v,
                            None => return 0,
                        },
                        BPF_ABS | BPF_IND => {
                            let off = if code & 0xe0 == BPF_IND { k.wrapping_add(x) } else { k };
                            match load(skb, off as i32, code & 0x18) {
                                Some(v) => v,
                                None => return 0,
                            }
                        }
                        BPF_MEM => mem[k as usize],
                        BPF_LEN => (skb.frame.len() - skb.data) as u32,
                        _ => k,
                    };
                }
                BPF_LDX => {
                    x = match code & 0xe0 {
                        BPF_MEM => mem[k as usize],
                        BPF_LEN => (skb.frame.len() - skb.data) as u32,
                        BPF_MSH => match load(skb, k as i32, BPF_B) {
                            Some(v) => (v & 0xf) << 2,
                            None => return 0,
                        },
                        _ => k,
                    };
                }
                BPF_ST => mem[k as usize] = a,
                BPF_STX => mem[k as usize] = x,
                BPF_ALU => {
                    let v = if code & BPF_X != 0 { x } else { k };
                    a = match code & 0xf0 {
                        BPF_ADD => a.wrapping_add(v),
                        BPF_SUB => a.wrapping_sub(v),
                        BPF_MUL => a.wrapping_mul(v),
                        BPF_DIV => match a.checked_div(v) {
                            Some(q) => q,
                            None => return 0,
                        },
                        BPF_MOD => match a.checked_rem(v) {
                            Some(r) => r,
                            None => return 0,
                        },
                        BPF_OR => a | v,
                        BPF_AND => a & v,
                        BPF_XOR => a ^ v,
                        BPF_LSH => a.wrapping_shl(v),
                        BPF_RSH => a.wrapping_shr(v),
                        BPF_NEG => a.wrapping_neg(),
                        _ => a,
                    };
                }
                BPF_JMP => {
                    let v = if code & BPF_X != 0 { x } else { k };
                    let jump = match code & 0xf0 {
                        BPF_JA => {
                            pc += k as usize;
                            continue;
                        }
                        BPF_JEQ => a == v,
                        BPF_JGT => a > v,
                        BPF_JGE => a >= v,
                        BPF_JSET => a & v != 0,
                        _ => false,
                    };
                    pc += usize::from(if jump { insn.jt } else { insn.jf });
                }
                BPF_RET => return if code & 0x18 == BPF_A { a } else { k },
                BPF_MISC => {
                    if code & 0xf8 == BPF_TXA {
                        a = x;
                    } else if code & 0xf8 == BPF_TAX {
                        x = a;
                    }
                }
                _ => return 0,
            }
        }
        0
    }
}

/// Loads a word, a half word or a byte in network byte order at `off`, as `bpf_internal_load_pointer_neg_helper`
/// and `skb_header_pointer` of Linux. An offset at `SKF_NET_OFF` or `SKF_LL_OFF` and more is
/// relative to the network or the link header. Gives `None` out of the packet.
fn load(skb: &Skb<'_>, off: i32, size: u16) -> Option<u32> {
    let start = if off >= 0 {
        skb.data.checked_add(off as usize)?
    } else if off >= SKF_NET_OFF {
        skb.net.checked_add((off - SKF_NET_OFF) as usize)?
    } else if off >= SKF_LL_OFF {
        skb.mac.checked_add((off - SKF_LL_OFF) as usize)?
    } else {
        return None;
    };
    let n = match size {
        BPF_W => 4,
        BPF_H => 2,
        _ => 1,
    };
    let b = skb.frame.get(start..start.checked_add(n)?)?;
    Some(b.iter().fold(0u32, |v, &c| (v << 8) | u32::from(c)))
}

/// Gives the datum of a load at `SKF_AD_OFF + ad`, as `convert_bpf_extensions` of Linux. The
/// packets here have no mark, no queue, no hash and no VLAN tag, so these data are 0. The
/// attributes of netlink and the offset of the payload are not here, and give 0.
fn ancillary(skb: &Skb<'_>, ad: u32, a: u32, x: u32) -> Option<u32> {
    Some(match ad {
        SKF_AD_PROTOCOL => u32::from(skb.protocol),
        SKF_AD_PKTTYPE => u32::from(skb.pkttype),
        SKF_AD_IFINDEX => skb.ifindex,
        SKF_AD_HATYPE => u32::from(skb.hatype),
        SKF_AD_ALU_XOR_X => a ^ x,
        SKF_AD_RANDOM => random(),
        SKF_AD_NLATTR
        | SKF_AD_NLATTR_NEST
        | SKF_AD_MARK
        | SKF_AD_QUEUE
        | SKF_AD_RXHASH
        | SKF_AD_CPU
        | SKF_AD_VLAN_TAG
        | SKF_AD_VLAN_TAG_PRESENT
        | SKF_AD_PAY_OFFSET
        | SKF_AD_VLAN_TPID => 0,
        _ => return None,
    })
}

/// A pseudo-random number for `SKF_AD_RANDOM`, as `bpf_user_rnd_u32` of Linux.
fn random() -> u32 {
    use core::sync::atomic::{AtomicU32, Ordering};
    static STATE: AtomicU32 = AtomicU32::new(0x2545_f491);
    let mut s = STATE.load(Ordering::Relaxed);
    s ^= s << 13;
    s ^= s >> 17;
    s ^= s << 5;
    STATE.store(s, Ordering::Relaxed);
    s
}

/// The filter of a socket and its lock: `sk_filter` and `SOCK_FILTER_LOCKED` of Linux.
#[derive(Debug, Default)]
pub struct SocketFilter {
    filter: Option<Filter>,
    locked: bool,
}

impl SocketFilter {
    /// The filter, if the socket has one.
    pub fn get(&self) -> Option<&Filter> {
        self.filter.as_ref()
    }

    /// `SO_ATTACH_FILTER`, `SO_DETACH_FILTER` and `SO_LOCK_FILTER`, as `sk_setsockopt` of Linux.
    /// For `SO_ATTACH_FILTER`, `value` has the instructions: the system call reads them from the
    /// `struct sock_fprog` of the caller. The new filter replaces the old filter.
    ///
    /// # Errors
    ///
    /// Gives `EPERM` if the filter is locked, `ENOENT` for `SO_DETACH_FILTER` without a filter,
    /// and `EINVAL` for a program that is not valid.
    pub fn set(&mut self, name: u32, value: &[u8]) -> Result<()> {
        use rk_abi::native::socket::{SO_ATTACH_FILTER, SO_DETACH_FILTER, SO_LOCK_FILTER};
        match name {
            SO_ATTACH_FILTER if self.locked => Err(Errno::EPERM),
            SO_ATTACH_FILTER => {
                self.filter = Some(Filter::new(value)?);
                Ok(())
            }
            SO_DETACH_FILTER if self.locked => Err(Errno::EPERM),
            SO_DETACH_FILTER => self.filter.take().map(|_| ()).ok_or(Errno::ENOENT),
            SO_LOCK_FILTER => {
                let v: [u8; 4] =
                    value.get(..4).and_then(|v| v.try_into().ok()).ok_or(Errno::EINVAL)?;
                let on = i32::from_ne_bytes(v) != 0;
                if self.locked && !on {
                    return Err(Errno::EPERM);
                }
                self.locked = on;
                Ok(())
            }
            _ => Err(Errno::ENOPROTOOPT),
        }
    }

    /// `getsockopt` of `SO_LOCK_FILTER`.
    pub fn locked(&self) -> bool {
        self.locked
    }
}
