//! The eBPF instructions, RFC 9669 and include/uapi/linux/bpf_common.h and bpf.h of Linux.
//!
//! The constants of the opcodes have the names of Linux and no comment each.
#![allow(missing_docs)]

use alloc::vec::Vec;

/// The size of one instruction.
pub const INSN_SIZE: usize = 8;

/// The most instructions of one program, `BPF_COMPLEXITY_LIMIT_INSNS` of Linux. A program
/// without `CAP_BPF` has at most `BPF_MAXINSNS`.
pub const BPF_COMPLEXITY_LIMIT_INSNS: u32 = 1_000_000;

/// The most instructions of a program of a process without `CAP_BPF`.
pub const BPF_MAXINSNS: u32 = 4096;

/// The size of the stack of a program, `MAX_BPF_STACK` of Linux.
pub const MAX_BPF_STACK: usize = 512;

/// The number of registers: R0 to R9 and the frame pointer R10.
pub const MAX_BPF_REG: usize = 11;

/// The frame pointer.
pub const BPF_REG_FP: u8 = 10;

// The instruction classes.
pub const BPF_LD: u8 = 0x00;
pub const BPF_LDX: u8 = 0x01;
pub const BPF_ST: u8 = 0x02;
pub const BPF_STX: u8 = 0x03;
pub const BPF_ALU: u8 = 0x04;
pub const BPF_JMP: u8 = 0x05;
pub const BPF_JMP32: u8 = 0x06;
pub const BPF_ALU64: u8 = 0x07;

// The sizes of the load and store instructions.
pub const BPF_W: u8 = 0x00;
pub const BPF_H: u8 = 0x08;
pub const BPF_B: u8 = 0x10;
pub const BPF_DW: u8 = 0x18;

// The modes of the load and store instructions.
pub const BPF_IMM: u8 = 0x00;
pub const BPF_ABS: u8 = 0x20;
pub const BPF_IND: u8 = 0x40;
pub const BPF_MEM: u8 = 0x60;
pub const BPF_MEMSX: u8 = 0x80;
pub const BPF_ATOMIC: u8 = 0xc0;

// The source of the ALU and jump instructions.
pub const BPF_K: u8 = 0x00;
pub const BPF_X: u8 = 0x08;

// The ALU operations.
pub const BPF_ADD: u8 = 0x00;
pub const BPF_SUB: u8 = 0x10;
pub const BPF_MUL: u8 = 0x20;
pub const BPF_DIV: u8 = 0x30;
pub const BPF_OR: u8 = 0x40;
pub const BPF_AND: u8 = 0x50;
pub const BPF_LSH: u8 = 0x60;
pub const BPF_RSH: u8 = 0x70;
pub const BPF_NEG: u8 = 0x80;
pub const BPF_MOD: u8 = 0x90;
pub const BPF_XOR: u8 = 0xa0;
pub const BPF_MOV: u8 = 0xb0;
pub const BPF_ARSH: u8 = 0xc0;
pub const BPF_END: u8 = 0xd0;

/// `BPF_END` to little endian, in the source field.
pub const BPF_TO_LE: u8 = 0x00;
/// `BPF_END` to big endian, in the source field.
pub const BPF_TO_BE: u8 = 0x08;

// The jump operations.
pub const BPF_JA: u8 = 0x00;
pub const BPF_JEQ: u8 = 0x10;
pub const BPF_JGT: u8 = 0x20;
pub const BPF_JGE: u8 = 0x30;
pub const BPF_JSET: u8 = 0x40;
pub const BPF_JNE: u8 = 0x50;
pub const BPF_JSGT: u8 = 0x60;
pub const BPF_JSGE: u8 = 0x70;
pub const BPF_CALL: u8 = 0x80;
pub const BPF_EXIT: u8 = 0x90;
pub const BPF_JLT: u8 = 0xa0;
pub const BPF_JLE: u8 = 0xb0;
pub const BPF_JSLT: u8 = 0xc0;
pub const BPF_JSLE: u8 = 0xd0;

// The atomic operations, in the immediate of `BPF_STX | BPF_ATOMIC`.
pub const BPF_FETCH: i32 = 0x01;
pub const BPF_XCHG: i32 = 0xe0 | BPF_FETCH;
pub const BPF_CMPXCHG: i32 = 0xf0 | BPF_FETCH;

/// The source register of `BPF_LD | BPF_IMM | BPF_DW` that has a map file descriptor.
pub const BPF_PSEUDO_MAP_FD: u8 = 1;
/// The source register of `BPF_LD | BPF_IMM | BPF_DW` that has the address of a map value.
pub const BPF_PSEUDO_MAP_VALUE: u8 = 2;
/// The source register of `BPF_CALL` for a call to a function of the program.
pub const BPF_PSEUDO_CALL: u8 = 1;

/// The class of an opcode.
pub const fn bpf_class(code: u8) -> u8 {
    code & 0x07
}

/// The size field of an opcode.
pub const fn bpf_size(code: u8) -> u8 {
    code & 0x18
}

/// The mode field of an opcode.
pub const fn bpf_mode(code: u8) -> u8 {
    code & 0xe0
}

/// The operation field of an ALU or jump opcode.
pub const fn bpf_op(code: u8) -> u8 {
    code & 0xf0
}

/// The source field of an ALU or jump opcode.
pub const fn bpf_src(code: u8) -> u8 {
    code & 0x08
}

/// The number of bytes of a size field, `bpf_size_to_bytes` of Linux.
pub const fn bpf_size_to_bytes(size: u8) -> u32 {
    match size {
        BPF_B => 1,
        BPF_H => 2,
        BPF_W => 4,
        _ => 8,
    }
}

/// One instruction, `struct bpf_insn` of Linux.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BpfInsn {
    /// The opcode.
    pub code: u8,
    /// The destination register.
    pub dst_reg: u8,
    /// The source register.
    pub src_reg: u8,
    /// The signed offset.
    pub off: i16,
    /// The signed immediate.
    pub imm: i32,
}

impl BpfInsn {
    /// Reads an instruction in the byte order of the machine.
    pub fn from_bytes(b: &[u8; INSN_SIZE]) -> Self {
        Self {
            code: b[0],
            dst_reg: b[1] & 0x0f,
            src_reg: b[1] >> 4,
            off: i16::from_ne_bytes([b[2], b[3]]),
            imm: i32::from_ne_bytes([b[4], b[5], b[6], b[7]]),
        }
    }

    /// Writes the instruction in the byte order of the machine.
    pub fn to_bytes(self) -> [u8; INSN_SIZE] {
        let mut b = [0u8; INSN_SIZE];
        b[0] = self.code;
        b[1] = (self.src_reg << 4) | (self.dst_reg & 0x0f);
        b[2..4].copy_from_slice(&self.off.to_ne_bytes());
        b[4..8].copy_from_slice(&self.imm.to_ne_bytes());
        b
    }

    /// Tells if this is the first half of `BPF_LD | BPF_IMM | BPF_DW`.
    pub fn is_ld_imm64(self) -> bool {
        self.code == BPF_LD | BPF_IMM | BPF_DW
    }
}

/// Reads the instructions of a program.
pub fn decode(bytes: &[u8]) -> Vec<BpfInsn> {
    bytes.as_chunks::<INSN_SIZE>().0.iter().map(BpfInsn::from_bytes).collect()
}

/// The instructions that a test writes, as the macros of include/linux/filter.h of Linux.
#[cfg(test)]
pub mod asm {
    use super::*;

    pub fn alu64_imm(op: u8, dst: u8, imm: i32) -> BpfInsn {
        BpfInsn { code: BPF_ALU64 | op | BPF_K, dst_reg: dst, src_reg: 0, off: 0, imm }
    }
    pub fn alu64_reg(op: u8, dst: u8, src: u8) -> BpfInsn {
        BpfInsn { code: BPF_ALU64 | op | BPF_X, dst_reg: dst, src_reg: src, off: 0, imm: 0 }
    }
    pub fn alu32_imm(op: u8, dst: u8, imm: i32) -> BpfInsn {
        BpfInsn { code: BPF_ALU | op | BPF_K, dst_reg: dst, src_reg: 0, off: 0, imm }
    }
    pub fn alu32_reg(op: u8, dst: u8, src: u8) -> BpfInsn {
        BpfInsn { code: BPF_ALU | op | BPF_X, dst_reg: dst, src_reg: src, off: 0, imm: 0 }
    }
    pub fn mov64_imm(dst: u8, imm: i32) -> BpfInsn {
        alu64_imm(BPF_MOV, dst, imm)
    }
    pub fn mov64_reg(dst: u8, src: u8) -> BpfInsn {
        alu64_reg(BPF_MOV, dst, src)
    }
    pub fn mov32_imm(dst: u8, imm: i32) -> BpfInsn {
        alu32_imm(BPF_MOV, dst, imm)
    }
    pub fn ld_imm64(dst: u8, src: u8, imm: u64) -> [BpfInsn; 2] {
        [
            BpfInsn {
                code: BPF_LD | BPF_IMM | BPF_DW,
                dst_reg: dst,
                src_reg: src,
                off: 0,
                imm: imm as u32 as i32,
            },
            BpfInsn { code: 0, dst_reg: 0, src_reg: 0, off: 0, imm: (imm >> 32) as u32 as i32 },
        ]
    }
    pub fn ldx_mem(size: u8, dst: u8, src: u8, off: i16) -> BpfInsn {
        BpfInsn { code: BPF_LDX | size | BPF_MEM, dst_reg: dst, src_reg: src, off, imm: 0 }
    }
    pub fn stx_mem(size: u8, dst: u8, src: u8, off: i16) -> BpfInsn {
        BpfInsn { code: BPF_STX | size | BPF_MEM, dst_reg: dst, src_reg: src, off, imm: 0 }
    }
    pub fn st_mem(size: u8, dst: u8, off: i16, imm: i32) -> BpfInsn {
        BpfInsn { code: BPF_ST | size | BPF_MEM, dst_reg: dst, src_reg: 0, off, imm }
    }
    pub fn atomic(size: u8, dst: u8, src: u8, off: i16, op: i32) -> BpfInsn {
        BpfInsn { code: BPF_STX | size | BPF_ATOMIC, dst_reg: dst, src_reg: src, off, imm: op }
    }
    pub fn jmp_imm(op: u8, dst: u8, imm: i32, off: i16) -> BpfInsn {
        BpfInsn { code: BPF_JMP | op | BPF_K, dst_reg: dst, src_reg: 0, off, imm }
    }
    pub fn jmp_reg(op: u8, dst: u8, src: u8, off: i16) -> BpfInsn {
        BpfInsn { code: BPF_JMP | op | BPF_X, dst_reg: dst, src_reg: src, off, imm: 0 }
    }
    pub fn call(func: i32) -> BpfInsn {
        BpfInsn { code: BPF_JMP | BPF_CALL, dst_reg: 0, src_reg: 0, off: 0, imm: func }
    }
    pub fn exit() -> BpfInsn {
        BpfInsn { code: BPF_JMP | BPF_EXIT, dst_reg: 0, src_reg: 0, off: 0, imm: 0 }
    }
}
