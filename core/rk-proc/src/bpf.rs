//! Classic BPF for the filters of `seccomp`: the check of a program and its interpreter.
//!
//! A filter is a program of classic BPF that gets the `seccomp_data` of a system call and gives
//! an action. The check accepts only the instructions that `seccomp_check_filter` of Linux
//! accepts, and the interpreter runs them as `__bpf_prog_run` of Linux runs the converted
//! program. The jumps go forward only, thus each program ends.

use alloc::vec::Vec;
use rk_abi::Errno;

/// The most instructions in one program, as `BPF_MAXINSNS` of Linux.
pub const BPF_MAXINSNS: usize = 4096;

/// The number of 32-bit words of the scratch memory.
const BPF_MEMWORDS: u32 = 16;

/// The size of `seccomp_data`: the number of the system call, the architecture, the instruction
/// pointer and six arguments.
pub const SECCOMP_DATA_SIZE: usize = 64;

/// The instruction classes.
const BPF_LD: u16 = 0x00;
const BPF_LDX: u16 = 0x01;
const BPF_ST: u16 = 0x02;
const BPF_STX: u16 = 0x03;
const BPF_ALU: u16 = 0x04;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;
const BPF_MISC: u16 = 0x07;

/// The mode of a load. A filter loads only 32-bit words.
const BPF_ABS: u16 = 0x20;
const BPF_MEM: u16 = 0x60;
const BPF_LEN: u16 = 0x80;

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
const BPF_XOR: u16 = 0xa0;
const BPF_JA: u16 = 0x00;
const BPF_JEQ: u16 = 0x10;
const BPF_JGT: u16 = 0x20;
const BPF_JGE: u16 = 0x30;
const BPF_JSET: u16 = 0x40;

/// The source of the operand: the constant `k` or the register X.
const BPF_K: u16 = 0x00;
const BPF_X: u16 = 0x08;
/// The value of a return: `k` or the register A.
const BPF_A: u16 = 0x10;

/// The operations of `BPF_MISC`.
const BPF_TAX: u16 = 0x00;
const BPF_TXA: u16 = 0x80;

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

/// The size of one instruction in user memory.
pub const INSN_SIZE: usize = 8;

impl Insn {
    /// Reads an instruction from its 8 bytes in user memory.
    pub fn from_bytes(b: &[u8]) -> Self {
        Self {
            code: u16::from_ne_bytes([b[0], b[1]]),
            jt: b[2],
            jf: b[3],
            k: u32::from_ne_bytes([b[4], b[5], b[6], b[7]]),
        }
    }

    /// Gives the 8 bytes of the instruction in user memory.
    pub fn to_bytes(self) -> [u8; INSN_SIZE] {
        let mut b = [0u8; INSN_SIZE];
        b[0..2].copy_from_slice(&self.code.to_ne_bytes());
        b[2] = self.jt;
        b[3] = self.jf;
        b[4..8].copy_from_slice(&self.k.to_ne_bytes());
        b
    }
}

/// Tells if `code` is an instruction that a filter of `seccomp` can have.
const fn allowed(code: u16) -> bool {
    const ALU_OPS: [u16; 9] =
        [BPF_ADD, BPF_SUB, BPF_MUL, BPF_DIV, BPF_AND, BPF_OR, BPF_XOR, BPF_LSH, BPF_RSH];
    const JMP_OPS: [u16; 4] = [BPF_JEQ, BPF_JGE, BPF_JGT, BPF_JSET];
    let mut i = 0;
    while i < ALU_OPS.len() {
        if code == BPF_ALU | ALU_OPS[i] | BPF_K || code == BPF_ALU | ALU_OPS[i] | BPF_X {
            return true;
        }
        i += 1;
    }
    let mut i = 0;
    while i < JMP_OPS.len() {
        if code == BPF_JMP | JMP_OPS[i] | BPF_K || code == BPF_JMP | JMP_OPS[i] | BPF_X {
            return true;
        }
        i += 1;
    }
    matches!(
        code,
        0x00 // BPF_LD | BPF_W | BPF_IMM
            | 0x20 // BPF_LD | BPF_W | BPF_ABS
            | 0x80 // BPF_LD | BPF_W | BPF_LEN
            | 0x60 // BPF_LD | BPF_W | BPF_MEM
            | 0x01 // BPF_LDX | BPF_W | BPF_IMM
            | 0x81 // BPF_LDX | BPF_W | BPF_LEN
            | 0x61 // BPF_LDX | BPF_W | BPF_MEM
            | 0x02 // BPF_ST
            | 0x03 // BPF_STX
            | 0x84 // BPF_ALU | BPF_NEG
            | 0x05 // BPF_JMP | BPF_JA
            | 0x06 // BPF_RET | BPF_K
            | 0x16 // BPF_RET | BPF_A
            | 0x07 // BPF_MISC | BPF_TAX
            | 0x87 // BPF_MISC | BPF_TXA
    )
}

/// Checks a program for `seccomp`, as `bpf_check_classic` and `seccomp_check_filter` of Linux
/// do. Each jump must stay in the program, the scratch memory has 16 words, a division by a
/// constant 0 and a shift of 32 or more are not valid, a load from `seccomp_data` must be an
/// aligned word in it, and the last instruction must be a return.
///
/// # Errors
///
/// Gives `EINVAL` if the program is empty, too long or not valid.
pub fn check(prog: &[Insn]) -> Result<(), Errno> {
    let len = prog.len();
    if len == 0 || len > BPF_MAXINSNS {
        return Err(Errno::EINVAL);
    }
    for (pc, insn) in prog.iter().enumerate() {
        let code = insn.code;
        let k = insn.k;
        if !allowed(code) {
            return Err(Errno::EINVAL);
        }
        let rest = len - pc - 1;
        let ok = match code & 0x07 {
            BPF_ALU => match code & 0xf0 {
                BPF_DIV if code & BPF_X == 0 => k != 0,
                BPF_LSH | BPF_RSH if code & BPF_X == 0 => k < 32,
                _ => true,
            },
            BPF_LD | BPF_LDX if code & 0xe0 == BPF_MEM => k < BPF_MEMWORDS,
            BPF_ST | BPF_STX => k < BPF_MEMWORDS,
            BPF_LD if code & 0xe0 == BPF_ABS => (k as usize) < SECCOMP_DATA_SIZE && k & 3 == 0,
            BPF_JMP if code & 0xf0 == BPF_JA => (k as usize) < rest,
            BPF_JMP => usize::from(insn.jt) < rest && usize::from(insn.jf) < rest,
            _ => true,
        };
        if !ok {
            return Err(Errno::EINVAL);
        }
    }
    match prog[len - 1].code {
        0x06 | 0x16 => Ok(()),
        _ => Err(Errno::EINVAL),
    }
}

/// Runs a program that `check` accepted on the `seccomp_data` in `data`. Gives the return value
/// of the program. A division by 0 in X ends the program with 0, as in Linux.
pub fn run(prog: &[Insn], data: &[u8; SECCOMP_DATA_SIZE]) -> u32 {
    let mut a: u32 = 0;
    let mut x: u32 = 0;
    let mut mem = [0u32; BPF_MEMWORDS as usize];
    let mut pc = 0;
    while let Some(insn) = prog.get(pc) {
        pc += 1;
        let k = insn.k;
        let code = insn.code;
        match code & 0x07 {
            BPF_LD => {
                a = match code & 0xe0 {
                    BPF_ABS => {
                        let o = k as usize;
                        u32::from_ne_bytes([data[o], data[o + 1], data[o + 2], data[o + 3]])
                    }
                    BPF_MEM => mem[k as usize],
                    BPF_LEN => SECCOMP_DATA_SIZE as u32,
                    _ => k,
                };
            }
            BPF_LDX => {
                x = match code & 0xe0 {
                    BPF_MEM => mem[k as usize],
                    BPF_LEN => SECCOMP_DATA_SIZE as u32,
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

/// Makes the `seccomp_data` of a system call: the number, the architecture, the address of the
/// instruction after the system call, and the six arguments.
pub fn seccomp_data(nr: i32, arch: u32, ip: u64, args: [u64; 6]) -> [u8; SECCOMP_DATA_SIZE] {
    let mut d = [0u8; SECCOMP_DATA_SIZE];
    d[0..4].copy_from_slice(&nr.to_ne_bytes());
    d[4..8].copy_from_slice(&arch.to_ne_bytes());
    d[8..16].copy_from_slice(&ip.to_ne_bytes());
    for (i, arg) in args.iter().enumerate() {
        d[16 + i * 8..24 + i * 8].copy_from_slice(&arg.to_ne_bytes());
    }
    d
}

/// Reads a program from its bytes in user memory.
pub fn from_bytes(b: &[u8]) -> Vec<Insn> {
    b.as_chunks::<INSN_SIZE>().0.iter().map(|c| Insn::from_bytes(c)).collect()
}
