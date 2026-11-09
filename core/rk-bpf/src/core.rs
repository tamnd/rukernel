//! The interpreter, `___bpf_prog_run` in kernel/bpf/core.c of Linux, for the instructions of
//! RFC 9669.
//!
//! The crate has no unsafe code, so a pointer of a program is not a machine address. It is the
//! number of a region and an offset in the region: the stack, the context, a map, or a map
//! value that a helper gave. Each access looks up the region and checks the bounds. The verifier
//! proves that the accesses are in bounds, so a failed check is a fault that must not occur. A
//! fault stops the program.
#![allow(non_upper_case_globals)]

use crate::helpers::{HelperEnv, bpf_user_rnd_u32, func::*};
use crate::insn::*;
use crate::map::{BpfMap, Elem};
use crate::prog::{BpfProg, ProgCtx};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;
use rk_abi::Errno;

/// The error of a run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BpfRunError {
    /// An access out of bounds or a bad instruction, which the verifier must stop.
    Fault,
}

type Result<T> = core::result::Result<T, BpfRunError>;
use BpfRunError::Fault;

/// The base of the addresses of the regions. It is not 0, so NULL is never a region.
const ADDR_BASE: u64 = 0xffff_a000_0000_0000;
/// The region of the stack.
const REGION_STACK: usize = 0;
/// The region of the context.
const REGION_CTX: usize = 1;
/// The first region of the maps of the program.
const REGION_MAP0: usize = 2;
/// The most map values that one run can look up.
const MAX_VALUES: usize = 1 << 16;
/// The most instructions of one run. The verifier refuses back edges, so a run is shorter.
const MAX_STEPS: u64 = 1 << 24;

/// The address of `off` in the region `idx`.
pub(crate) const fn region_addr(idx: usize, off: u32) -> u64 {
    ADDR_BASE + ((idx as u64) << 32) + off as u64
}

/// The address of the map `i` of the program, for `BPF_PSEUDO_MAP_FD`.
pub(crate) const fn map_addr(i: usize) -> u64 {
    region_addr(REGION_MAP0 + i, 0)
}

/// A place in memory.
enum Loc {
    Stack(usize),
    Ctx(u32),
    Map(usize),
    Value(usize, usize),
}

/// A map value that the program looked up.
struct Value {
    elem: Arc<Elem>,
    cpu: usize,
    size: usize,
}

/// The bytes of the stack of all the frames. The frame `k` has the bytes from `k * 512` to
/// `(k + 1) * 512`, and its frame pointer is at the end.
const STACK_SIZE: usize = MAX_BPF_STACK * MAX_CALL_FRAMES;

/// `SKF_NET_OFF` of include/uapi/linux/filter.h: a negative offset of a packet load that
/// starts at the network header.
const SKF_NET_OFF: i32 = -0x100000;

/// The most tail calls of one run, `MAX_TAIL_CALL_CNT` of Linux.
pub const MAX_TAIL_CALL_CNT: u32 = 33;

/// The state of one run.
struct Run<'a> {
    prog: &'a BpfProg,
    /// The program of the last tail call. It runs in place of `prog`.
    tail: Option<Arc<BpfProg>>,
    /// The count of the tail calls, `tail_call_cnt` of Linux.
    tail_call_cnt: u32,
    ctx: &'a mut dyn ProgCtx,
    env: &'a dyn HelperEnv,
    stack: Vec<u8>,
    values: Vec<Value>,
    /// The entry of `values` of the value of each map of the program that a
    /// `BPF_PSEUDO_MAP_VALUE` load gave.
    direct: Vec<Option<usize>>,
}

/// The state of a caller, for a call of a function of the program.
struct CallFrame {
    /// The instruction after the call.
    ret: usize,
    /// The registers of the caller. The call keeps them, except R0.
    regs: [u64; MAX_BPF_REG],
}

/// Runs `prog` with the context `ctx` and gives R0, as `bpf_prog_run` of Linux.
pub fn bpf_prog_run(prog: &BpfProg, ctx: &mut dyn ProgCtx, env: &dyn HelperEnv) -> Result<u64> {
    let mut run = Run {
        prog,
        tail: None,
        tail_call_cnt: 0,
        ctx,
        env,
        stack: vec![0; STACK_SIZE],
        values: Vec::new(),
        direct: vec![None; prog.used_maps.len()],
    };
    run.exec()
}

/// The ALU operations of 64 bits.
fn alu64(op: u8, off: i16, dst: u64, src: u64) -> Option<u64> {
    let (sd, ss) = (dst as i64, src as i64);
    Some(match op {
        BPF_ADD => dst.wrapping_add(src),
        BPF_SUB => dst.wrapping_sub(src),
        BPF_MUL => dst.wrapping_mul(src),
        BPF_DIV if src == 0 => 0,
        BPF_DIV if off == 1 => sd.wrapping_div(ss) as u64,
        BPF_DIV => dst / src,
        BPF_MOD if src == 0 => dst,
        BPF_MOD if off == 1 => sd.wrapping_rem(ss) as u64,
        BPF_MOD => dst % src,
        BPF_OR => dst | src,
        BPF_AND => dst & src,
        BPF_XOR => dst ^ src,
        BPF_LSH => dst << (src & 63),
        BPF_RSH => dst >> (src & 63),
        BPF_ARSH => (sd >> (src & 63)) as u64,
        BPF_NEG => sd.wrapping_neg() as u64,
        BPF_MOV => match off {
            8 => src as i8 as i64 as u64,
            16 => src as i16 as i64 as u64,
            32 => src as i32 as i64 as u64,
            _ => src,
        },
        _ => return None,
    })
}

/// The ALU operations of 32 bits. The result is zero-extended.
fn alu32(op: u8, off: i16, dst: u32, src: u32) -> Option<u32> {
    let (sd, ss) = (dst as i32, src as i32);
    Some(match op {
        BPF_ADD => dst.wrapping_add(src),
        BPF_SUB => dst.wrapping_sub(src),
        BPF_MUL => dst.wrapping_mul(src),
        BPF_DIV if src == 0 => 0,
        BPF_DIV if off == 1 => sd.wrapping_div(ss) as u32,
        BPF_DIV => dst / src,
        BPF_MOD if src == 0 => dst,
        BPF_MOD if off == 1 => sd.wrapping_rem(ss) as u32,
        BPF_MOD => dst % src,
        BPF_OR => dst | src,
        BPF_AND => dst & src,
        BPF_XOR => dst ^ src,
        BPF_LSH => dst << (src & 31),
        BPF_RSH => dst >> (src & 31),
        BPF_ARSH => (sd >> (src & 31)) as u32,
        BPF_NEG => sd.wrapping_neg() as u32,
        BPF_MOV => match off {
            8 => src as i8 as i32 as u32,
            16 => src as i16 as i32 as u32,
            _ => src,
        },
        _ => return None,
    })
}

/// `BPF_END`: the byte order changes of `imm` bits.
fn endian(class: u8, src: u8, imm: i32, dst: u64) -> Option<u64> {
    let swap = class == BPF_ALU64
        || (src == BPF_TO_BE && cfg!(target_endian = "little"))
        || (src == BPF_TO_LE && cfg!(target_endian = "big"));
    Some(match (imm, swap) {
        (16, false) => dst as u16 as u64,
        (16, true) => (dst as u16).swap_bytes() as u64,
        (32, false) => dst as u32 as u64,
        (32, true) => (dst as u32).swap_bytes() as u64,
        (64, false) => dst,
        (64, true) => dst.swap_bytes(),
        _ => return None,
    })
}

/// The condition of a jump.
fn cond(op: u8, a: u64, b: u64, bits32: bool) -> Option<bool> {
    let (a, b) = if bits32 { (a as u32 as u64, b as u32 as u64) } else { (a, b) };
    let (sa, sb) = if bits32 { (a as i32 as i64, b as i32 as i64) } else { (a as i64, b as i64) };
    Some(match op {
        BPF_JEQ => a == b,
        BPF_JNE => a != b,
        BPF_JGT => a > b,
        BPF_JGE => a >= b,
        BPF_JLT => a < b,
        BPF_JLE => a <= b,
        BPF_JSET => a & b != 0,
        BPF_JSGT => sa > sb,
        BPF_JSGE => sa >= sb,
        BPF_JSLT => sa < sb,
        BPF_JSLE => sa <= sb,
        _ => return None,
    })
}

/// Sign-extends the low `size` bytes of `v`.
fn sign_extend(v: u64, size: u32) -> u64 {
    match size {
        1 => v as i8 as i64 as u64,
        2 => v as i16 as i64 as u64,
        4 => v as i32 as i64 as u64,
        _ => v,
    }
}

/// A negative errno as a result of a helper.
fn neg_errno(e: Errno) -> u64 {
    (-i64::from(e.get())) as u64
}

impl Run<'_> {
    /// The program that runs now.
    fn cur(&self) -> &BpfProg {
        self.tail.as_deref().unwrap_or(self.prog)
    }

    fn exec(&mut self) -> Result<u64> {
        let mut regs = [0u64; MAX_BPF_REG];
        regs[1] = region_addr(REGION_CTX, 0);
        regs[BPF_REG_FP as usize] = region_addr(REGION_STACK, MAX_BPF_STACK as u32);
        let mut pc = 0usize;
        let mut steps = 0u64;
        let mut frames: Vec<CallFrame> = Vec::new();
        loop {
            steps += 1;
            if steps > MAX_STEPS {
                return Err(Fault);
            }
            let insn = *self.cur().insns.get(pc).ok_or(Fault)?;
            pc += 1;
            let d = insn.dst_reg as usize;
            let s = insn.src_reg as usize;
            if d >= MAX_BPF_REG || s >= MAX_BPF_REG {
                return Err(Fault);
            }
            let class = bpf_class(insn.code);
            match class {
                BPF_ALU64 | BPF_ALU => {
                    let op = bpf_op(insn.code);
                    if op == BPF_END {
                        regs[d] =
                            endian(class, bpf_src(insn.code), insn.imm, regs[d]).ok_or(Fault)?;
                        continue;
                    }
                    let x = bpf_src(insn.code) == BPF_X;
                    regs[d] = if class == BPF_ALU64 {
                        let src = if x { regs[s] } else { insn.imm as i64 as u64 };
                        alu64(op, insn.off, regs[d], src).ok_or(Fault)?
                    } else {
                        let src = if x { regs[s] as u32 } else { insn.imm as u32 };
                        u64::from(alu32(op, insn.off, regs[d] as u32, src).ok_or(Fault)?)
                    };
                }
                BPF_JMP | BPF_JMP32 => {
                    let op = bpf_op(insn.code);
                    match op {
                        BPF_JA => {
                            let off =
                                if class == BPF_JMP32 { insn.imm as i64 } else { insn.off as i64 };
                            pc = (pc as i64 + off) as usize;
                        }
                        BPF_EXIT => match frames.pop() {
                            // The end of a function: the caller gets its registers back and R0.
                            Some(f) => {
                                let r0 = regs[0];
                                regs = f.regs;
                                regs[0] = r0;
                                pc = f.ret;
                            }
                            None => return Ok(regs[0]),
                        },
                        BPF_CALL
                            if class == BPF_JMP
                                && insn.src_reg == 0
                                && insn.imm == BPF_FUNC_tail_call =>
                        {
                            if let Some(prog) = self.tail_call(&regs)? {
                                // The registers and the stack stay. The verifier of the new
                                // program lets it read only R1, R10 and what it writes.
                                self.direct = vec![None; prog.used_maps.len()];
                                self.values.clear();
                                self.tail = Some(prog);
                                pc = 0;
                            }
                        }
                        BPF_CALL if class == BPF_JMP && insn.src_reg == 0 => {
                            regs[0] = self.call(insn.imm, &regs)?;
                        }
                        // A call of a function of the program, `JMP_CALL_ARGS` of Linux: the
                        // function gets R1 to R5 and a new frame of the stack.
                        BPF_CALL if class == BPF_JMP && insn.src_reg == BPF_PSEUDO_CALL => {
                            if frames.len() + 1 >= MAX_CALL_FRAMES {
                                return Err(Fault);
                            }
                            frames.push(CallFrame { ret: pc, regs });
                            let fp = (frames.len() + 1) * MAX_BPF_STACK;
                            regs[BPF_REG_FP as usize] = region_addr(REGION_STACK, fp as u32);
                            pc = (pc as i64 + insn.imm as i64) as usize;
                        }
                        _ => {
                            let b = if bpf_src(insn.code) == BPF_X {
                                regs[s]
                            } else {
                                insn.imm as i64 as u64
                            };
                            if cond(op, regs[d], b, class == BPF_JMP32).ok_or(Fault)? {
                                pc = (pc as i64 + insn.off as i64) as usize;
                            }
                        }
                    }
                }
                BPF_LDX => {
                    let size = bpf_size_to_bytes(bpf_size(insn.code));
                    let addr = regs[s].wrapping_add(insn.off as i64 as u64);
                    let v = self.load(addr, size)?;
                    regs[d] = match bpf_mode(insn.code) {
                        BPF_MEM => v,
                        BPF_MEMSX => sign_extend(v, size),
                        _ => return Err(Fault),
                    };
                }
                BPF_ST | BPF_STX => {
                    let size = bpf_size_to_bytes(bpf_size(insn.code));
                    let addr = regs[d].wrapping_add(insn.off as i64 as u64);
                    match (class, bpf_mode(insn.code)) {
                        (BPF_ST, BPF_MEM) => self.store(addr, size, insn.imm as i64 as u64)?,
                        (BPF_STX, BPF_MEM) => self.store(addr, size, regs[s])?,
                        (BPF_STX, BPF_ATOMIC) => self.atomic(addr, size, insn.imm, s, &mut regs)?,
                        _ => return Err(Fault),
                    }
                }
                BPF_LD if insn.is_ld_imm64() => {
                    let next = *self.cur().insns.get(pc).ok_or(Fault)?;
                    pc += 1;
                    regs[d] = match insn.src_reg {
                        0 => u64::from(insn.imm as u32) | (u64::from(next.imm as u32) << 32),
                        BPF_PSEUDO_MAP_FD => map_addr(insn.imm as usize),
                        BPF_PSEUDO_MAP_VALUE => {
                            self.direct_value(insn.imm as usize, next.imm as u32)?
                        }
                        _ => return Err(Fault),
                    };
                }
                BPF_LD if matches!(bpf_mode(insn.code), BPF_ABS | BPF_IND) => {
                    let off = if bpf_mode(insn.code) == BPF_IND {
                        regs[s].wrapping_add(insn.imm as i64 as u64) as i32
                    } else {
                        insn.imm
                    };
                    let size = bpf_size_to_bytes(bpf_size(insn.code));
                    match self.ld_abs(off, size) {
                        Some(v) => regs[0] = v,
                        // The load is out of the packet, so the program ends with 0, as
                        // `bpf_gen_ld_abs` of Linux.
                        None => return Ok(0),
                    }
                    // The load is a call of a helper, so R1 to R5 are not kept.
                    regs[1..=5].fill(0);
                }
                _ => return Err(Fault),
            }
        }
    }

    /// Finds the place of `size` bytes at `addr`.
    fn locate(&self, addr: u64, size: usize) -> Result<Loc> {
        let rel = addr.checked_sub(ADDR_BASE).ok_or(Fault)?;
        let idx = (rel >> 32) as usize;
        let off = rel as u32 as usize;
        let end = off.checked_add(size).ok_or(Fault)?;
        let nmaps = self.cur().used_maps.len();
        match idx {
            REGION_STACK if end <= STACK_SIZE => Ok(Loc::Stack(off)),
            REGION_CTX => Ok(Loc::Ctx(off as u32)),
            i if (REGION_MAP0..REGION_MAP0 + nmaps).contains(&i) && off == 0 => {
                Ok(Loc::Map(i - REGION_MAP0))
            }
            i if i >= REGION_MAP0 + nmaps => {
                let v = i - REGION_MAP0 - nmaps;
                let value = self.values.get(v).ok_or(Fault)?;
                if end <= value.size { Ok(Loc::Value(v, off)) } else { Err(Fault) }
            }
            _ => Err(Fault),
        }
    }

    fn load(&self, addr: u64, size: u32) -> Result<u64> {
        match self.locate(addr, size as usize)? {
            Loc::Ctx(off) => self.ctx.load(off, size).ok_or(Fault),
            _ => {
                let mut b = [0u8; 8];
                self.read_bytes(addr, &mut b[..size as usize])?;
                Ok(u64::from_le_bytes(b))
            }
        }
    }

    fn store(&mut self, addr: u64, size: u32, v: u64) -> Result<()> {
        match self.locate(addr, size as usize)? {
            Loc::Ctx(off) => self.ctx.store(off, size, v).ok_or(Fault),
            _ => self.write_bytes(addr, &v.to_le_bytes()[..size as usize]),
        }
    }

    /// Reads bytes of the stack or of a map value.
    fn read_bytes(&self, addr: u64, out: &mut [u8]) -> Result<()> {
        match self.locate(addr, out.len())? {
            Loc::Stack(off) => out.copy_from_slice(&self.stack[off..off + out.len()]),
            Loc::Value(v, off) => {
                let value = &self.values[v];
                value.elem.value(value.cpu).read(off, out);
            }
            Loc::Ctx(_) | Loc::Map(_) => return Err(Fault),
        }
        Ok(())
    }

    /// Writes bytes to the stack or to a map value.
    fn write_bytes(&mut self, addr: u64, data: &[u8]) -> Result<()> {
        match self.locate(addr, data.len())? {
            Loc::Stack(off) => self.stack[off..off + data.len()].copy_from_slice(data),
            Loc::Value(v, off) => {
                let value = &self.values[v];
                value.elem.value(value.cpu).write(off, data);
            }
            Loc::Ctx(_) | Loc::Map(_) => return Err(Fault),
        }
        Ok(())
    }

    /// `BPF_STX | BPF_ATOMIC`, as the `ATOMIC` cases of `___bpf_prog_run`.
    fn atomic(
        &mut self,
        addr: u64,
        size: u32,
        imm: i32,
        s: usize,
        regs: &mut [u64; MAX_BPF_REG],
    ) -> Result<()> {
        if size != 4 && size != 8 || !addr.is_multiple_of(u64::from(size)) {
            return Err(Fault);
        }
        let mask = if size == 4 { u64::from(u32::MAX) } else { u64::MAX };
        let src = regs[s] & mask;
        let expected = regs[0] & mask;
        let op = |old: u64| -> Option<u64> {
            Some(match imm & !BPF_FETCH {
                x if x == BPF_ADD as i32 => old.wrapping_add(src) & mask,
                x if x == BPF_OR as i32 => old | src,
                x if x == BPF_AND as i32 => old & src,
                x if x == BPF_XOR as i32 => old ^ src,
                0xe0 if imm == BPF_XCHG => src,
                0xf0 if imm == BPF_CMPXCHG => {
                    if old == expected {
                        src
                    } else {
                        old
                    }
                }
                _ => return None,
            })
        };
        let old = match self.locate(addr, size as usize)? {
            Loc::Stack(off) => {
                let mut b = [0u8; 8];
                b[..size as usize].copy_from_slice(&self.stack[off..off + size as usize]);
                let old = u64::from_le_bytes(b);
                let new = op(old).ok_or(Fault)?;
                self.stack[off..off + size as usize]
                    .copy_from_slice(&new.to_le_bytes()[..size as usize]);
                old
            }
            Loc::Value(v, off) => {
                let value = &self.values[v];
                let word = value.elem.value(value.cpu).word(off / 8).ok_or(Fault)?;
                let shift = (off % 8) as u32 * 8;
                let wmask = mask << shift;
                let mut bad = false;
                let prev = word
                    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |w| {
                        let old = (w & wmask) >> shift;
                        match op(old) {
                            Some(new) => Some((w & !wmask) | (new << shift)),
                            None => {
                                bad = true;
                                None
                            }
                        }
                    })
                    .unwrap_or(0);
                if bad {
                    return Err(Fault);
                }
                (prev & wmask) >> shift
            }
            Loc::Ctx(_) | Loc::Map(_) => return Err(Fault),
        };
        if imm == BPF_CMPXCHG {
            regs[0] = old;
        } else if imm & BPF_FETCH != 0 {
            regs[s] = old;
        }
        Ok(())
    }

    /// The address of the byte `off` of the value of the map `i` of the program, for a
    /// `BPF_PSEUDO_MAP_VALUE` load, as `array_map_direct_value_addr` of Linux. The verifier
    /// allows it only for an array of one value.
    fn direct_value(&mut self, i: usize, off: u32) -> Result<u64> {
        let v = match *self.direct.get(i).ok_or(Fault)? {
            Some(v) => v,
            None => {
                let map = self.cur().used_maps[i].clone();
                let elem = map.ops.map_lookup_elem(&0u32.to_le_bytes()).ok_or(Fault)?;
                if self.values.len() >= MAX_VALUES {
                    return Err(Fault);
                }
                self.values.push(Value { elem, cpu: 0, size: map.value_size as usize });
                self.direct[i] = Some(self.values.len() - 1);
                self.values.len() - 1
            }
        };
        Ok(region_addr(REGION_MAP0 + self.cur().used_maps.len() + v, off))
    }

    /// `BPF_LD | BPF_ABS` and `BPF_LD | BPF_IND`: reads `size` bytes of the packet at `off` in
    /// network byte order, as `bpf_skb_load_helper_8_no_cache` and the other sizes in
    /// net/core/filter.c of Linux. A negative offset from `SKF_NET_OFF` starts at the network
    /// header, which is the start of the data of a socket. The data has no link layer header,
    /// so a lower offset, such as `SKF_LL_OFF`, fails, as in Linux when the header is not set.
    fn ld_abs(&self, off: i32, size: u32) -> Option<u64> {
        let data = self.ctx.skb_data()?;
        let start = if off >= 0 {
            off as usize
        } else if off >= SKF_NET_OFF {
            (off - SKF_NET_OFF) as usize
        } else {
            return None;
        };
        let b = data.get(start..start.checked_add(size as usize)?)?;
        Some(b.iter().fold(0u64, |v, &x| (v << 8) | u64::from(x)))
    }

    /// `bpf_tail_call`, as `JMP_TAIL_CALL` of Linux: the program at the index R3 of the
    /// program array R2. An index out of the array, too many tail calls or an empty slot give
    /// `None`, and the caller continues.
    fn tail_call(&mut self, regs: &[u64; MAX_BPF_REG]) -> Result<Option<Arc<BpfProg>>> {
        let map = self.map_arg(regs[2])?;
        let array = map.ops.as_prog_array().ok_or(Fault)?;
        let index = regs[3] as u32;
        if index >= map.max_entries || self.tail_call_cnt >= MAX_TAIL_CALL_CNT {
            return Ok(None);
        }
        // Linux counts the call before it reads the slot.
        self.tail_call_cnt += 1;
        Ok(array.get(index))
    }

    /// The map of an argument.
    fn map_arg(&self, addr: u64) -> Result<Arc<BpfMap>> {
        match self.locate(addr, 0)? {
            Loc::Map(i) => Ok(self.cur().used_maps[i].clone()),
            _ => Err(Fault),
        }
    }

    /// Reads `n` bytes of a key or a value argument.
    fn arg_bytes(&self, addr: u64, n: u32) -> Result<Vec<u8>> {
        let mut b = vec![0u8; n as usize];
        self.read_bytes(addr, &mut b)?;
        Ok(b)
    }

    /// Runs the helper `id`, as the `bpf_*` functions of kernel/bpf/helpers.c of Linux.
    fn call(&mut self, id: i32, regs: &[u64; MAX_BPF_REG]) -> Result<u64> {
        let env = self.env;
        Ok(match id {
            BPF_FUNC_map_lookup_elem => {
                let map = self.map_arg(regs[1])?;
                let key = self.arg_bytes(regs[2], map.key_size)?;
                match map.ops.map_lookup_elem(&key) {
                    Some(elem) => {
                        if self.values.len() >= MAX_VALUES {
                            return Err(Fault);
                        }
                        let cpu = if map.is_percpu() { env.map_env().cpu } else { 0 };
                        let size = map.value_size as usize;
                        self.values.push(Value { elem, cpu, size });
                        let idx = REGION_MAP0 + self.cur().used_maps.len() + self.values.len() - 1;
                        region_addr(idx, 0)
                    }
                    None => 0,
                }
            }
            BPF_FUNC_map_update_elem => {
                let map = self.map_arg(regs[1])?;
                let key = self.arg_bytes(regs[2], map.key_size)?;
                let value = self.arg_bytes(regs[3], map.value_size)?;
                match map.ops.map_update_elem(&key, &value, regs[4], false, env.map_env()) {
                    Ok(()) => 0,
                    Err(e) => neg_errno(e),
                }
            }
            BPF_FUNC_map_delete_elem => {
                let map = self.map_arg(regs[1])?;
                let key = self.arg_bytes(regs[2], map.key_size)?;
                match map.ops.map_delete_elem(&key) {
                    Ok(()) => 0,
                    Err(e) => neg_errno(e),
                }
            }
            BPF_FUNC_get_prandom_u32 => u64::from(bpf_user_rnd_u32(env.ktime_get_ns())),
            BPF_FUNC_get_smp_processor_id => env.map_env().cpu as u64,
            BPF_FUNC_get_numa_node_id => 0,
            BPF_FUNC_ktime_get_ns | BPF_FUNC_ktime_get_boot_ns => env.ktime_get_ns(),
            BPF_FUNC_get_current_pid_tgid => {
                env.current_pid_tgid().unwrap_or_else(|| neg_errno(Errno::EINVAL))
            }
            BPF_FUNC_get_current_uid_gid => {
                env.current_uid_gid().unwrap_or_else(|| neg_errno(Errno::EINVAL))
            }
            BPF_FUNC_get_current_cgroup_id => env.current_cgroup_id(),
            BPF_FUNC_skb_load_bytes => self.skb_load_bytes(regs)?,
            _ => return Err(Fault),
        })
    }

    /// `bpf_skb_load_bytes` of net/core/filter.c.
    fn skb_load_bytes(&mut self, regs: &[u64; MAX_BPF_REG]) -> Result<u64> {
        let offset = regs[2] as u32;
        let len = regs[4] as u32 as usize;
        let bytes = match self.ctx.skb_data() {
            Some(data) if offset <= i32::MAX as u32 => {
                let start = offset as usize;
                data.get(start..start.saturating_add(len)).map(|b| b.to_vec())
            }
            _ => None,
        };
        match bytes {
            Some(b) => {
                self.write_bytes(regs[3], &b)?;
                Ok(0)
            }
            None => {
                self.write_bytes(regs[3], &vec![0u8; len])?;
                Ok(neg_errno(Errno::EFAULT))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::insn::asm::*;
    use crate::map::MapEnv;
    use crate::prog::SkBuff;

    pub(crate) struct NoEnv;

    impl HelperEnv for NoEnv {
        fn map_env(&self) -> MapEnv {
            MapEnv { nr_cpus: 1, cpu: 0 }
        }
        fn ktime_get_ns(&self) -> u64 {
            1000
        }
        fn current_pid_tgid(&self) -> Option<u64> {
            Some((7 << 32) | 8)
        }
        fn current_uid_gid(&self) -> Option<u64> {
            Some((5 << 32) | 6)
        }
        fn current_cgroup_id(&self) -> u64 {
            1
        }
    }

    fn prog(insns: &[BpfInsn], maps: Vec<Arc<BpfMap>>) -> BpfProg {
        BpfProg {
            prog_type: 1,
            expected_attach_type: 0,
            insns: insns.to_vec(),
            used_maps: maps,
            id: 0,
            name: [0; 16],
            tag: [0; 8],
            gpl_compatible: true,
            verified_insns: 0,
            run_cnt: core::sync::atomic::AtomicU64::new(0),
            load_time: 0,
            uid: 0,
            enforce_expected_attach_type: false,
        }
    }

    fn run(insns: &[BpfInsn]) -> u64 {
        let mut skb = SkBuff { data: b"abcdefgh", ..SkBuff::default() };
        bpf_prog_run(&prog(insns, Vec::new()), &mut skb, &NoEnv).unwrap()
    }

    #[test]
    fn alu64_and_alu32() {
        assert_eq!(run(&[mov64_imm(0, -1), alu64_imm(BPF_ADD, 0, 2), exit()]), 1);
        // A 32-bit operation clears the high bits.
        assert_eq!(run(&[mov64_imm(0, -1), alu32_imm(BPF_ADD, 0, 0), exit()]), 0xffff_ffff);
        assert_eq!(run(&[mov32_imm(0, -1), alu64_imm(BPF_ADD, 0, 1), exit()]), 1 << 32);
        assert_eq!(run(&[mov64_imm(0, -8), alu64_imm(BPF_ARSH, 0, 1), exit()]), -4i64 as u64);
        assert_eq!(run(&[mov64_imm(0, 1), alu64_imm(BPF_LSH, 0, 65), exit()]), 2);
        assert_eq!(run(&[mov64_imm(0, 5), alu64_imm(BPF_NEG, 0, 0), exit()]), -5i64 as u64);
    }

    #[test]
    fn division_by_zero() {
        // Division by zero gives 0, and modulo by zero keeps the dividend.
        let r = run(&[mov64_imm(0, 9), mov64_imm(1, 0), alu64_reg(BPF_DIV, 0, 1), exit()]);
        assert_eq!(r, 0);
        let r = run(&[mov64_imm(0, 9), mov64_imm(1, 0), alu64_reg(BPF_MOD, 0, 1), exit()]);
        assert_eq!(r, 9);
        // bpf_prog05: w7 = -1, w7 /= w6 with r6 = 1 << 32 gives 0, and w7 %= w6 gives the
        // low 32 bits of -1.
        let [a, b] = ld_imm64(6, 0, 1 << 32);
        let r = run(&[a, b, mov64_imm(0, -1), alu32_reg(BPF_DIV, 0, 6), exit()]);
        assert_eq!(r, 0);
        let r = run(&[a, b, mov64_imm(0, -1), alu32_reg(BPF_MOD, 0, 6), exit()]);
        assert_eq!(r, 0xffff_ffff);
        // A signed division.
        let mut sdiv = alu64_imm(BPF_DIV, 0, 2);
        sdiv.off = 1;
        assert_eq!(run(&[mov64_imm(0, -7), sdiv, exit()]), -3i64 as u64);
        let mut smod = alu64_imm(BPF_MOD, 0, -1);
        smod.off = 1;
        assert_eq!(run(&[mov64_imm(0, i32::MIN), smod, exit()]), 0);
    }

    #[test]
    fn movsx_and_endian() {
        let mut movsx = mov64_reg(0, 1);
        movsx.off = 8;
        assert_eq!(run(&[mov64_imm(1, 0x80), movsx, exit()]), -128i64 as u64);
        let be16 = BpfInsn {
            code: BPF_ALU | BPF_END | BPF_TO_BE,
            dst_reg: 0,
            imm: 16,
            ..BpfInsn::default()
        };
        assert_eq!(run(&[mov64_imm(0, 0x11_2233), be16, exit()]), 0x3322);
        let bswap64 =
            BpfInsn { code: BPF_ALU64 | BPF_END, dst_reg: 0, imm: 64, ..BpfInsn::default() };
        let [a, b] = ld_imm64(0, 0, 0x0102_0304_0506_0708);
        assert_eq!(run(&[a, b, bswap64, exit()]), 0x0807_0605_0403_0201);
    }

    #[test]
    fn jumps() {
        let r = run(&[
            mov64_imm(0, 1),
            mov64_imm(1, -1),
            jmp_imm(BPF_JSGT, 1, 0, 1),
            mov64_imm(0, 2),
            exit(),
        ]);
        assert_eq!(r, 2);
        let mut j32 = jmp_imm(BPF_JEQ, 1, 0, 1);
        j32.code = BPF_JMP32 | BPF_JEQ | BPF_K;
        let r = run(&[
            mov64_imm(0, 1),
            mov32_imm(1, 0),
            alu64_imm(BPF_ADD, 1, 0),
            j32,
            mov64_imm(0, 3),
            exit(),
        ]);
        assert_eq!(r, 1);
    }

    #[test]
    fn stack_atomics_and_ctx() {
        let r = run(&[
            st_mem(BPF_DW, BPF_REG_FP, -8, 10),
            mov64_imm(1, 5),
            atomic(BPF_DW, BPF_REG_FP, 1, -8, BPF_ADD as i32 | BPF_FETCH),
            ldx_mem(BPF_DW, 0, BPF_REG_FP, -8),
            alu64_reg(BPF_MUL, 0, 1),
            exit(),
        ]);
        // R1 gets the old value 10, and the stack has 15.
        assert_eq!(r, 150);
        let r = run(&[
            st_mem(BPF_W, BPF_REG_FP, -4, 3),
            mov64_imm(0, 3),
            mov64_imm(2, 9),
            atomic(BPF_W, BPF_REG_FP, 2, -4, BPF_CMPXCHG),
            ldx_mem(BPF_W, 0, BPF_REG_FP, -4),
            exit(),
        ]);
        assert_eq!(r, 9);
        // The length of the packet.
        assert_eq!(run(&[ldx_mem(BPF_W, 0, 1, 0), exit()]), 8);
    }

    #[test]
    fn skb_load_bytes_reads_the_packet() {
        let r = run(&[
            mov64_imm(2, 2),
            mov64_reg(3, BPF_REG_FP),
            alu64_imm(BPF_ADD, 3, -8),
            mov64_imm(4, 4),
            call(BPF_FUNC_skb_load_bytes),
            ldx_mem(BPF_W, 0, BPF_REG_FP, -8),
            exit(),
        ]);
        assert_eq!(r, u64::from(u32::from_le_bytes(*b"cdef")));
    }

    #[test]
    fn an_access_out_of_the_stack_is_a_fault() {
        // The frame pointer of the main program is at the end of its frame, and the frames
        // of the calls come after it.
        let end = (STACK_SIZE - MAX_BPF_STACK) as i16;
        let p = prog(&[ldx_mem(BPF_DW, 0, BPF_REG_FP, end), exit()], Vec::new());
        let mut skb = SkBuff::default();
        assert_eq!(bpf_prog_run(&p, &mut skb, &NoEnv), Err(Fault));
    }

    #[test]
    fn calls_of_functions_of_the_program() {
        // main: R6 = 100, R0 = f(5) + R6. f: R6 = 1, R0 = R1 * 2 + the stack of f.
        let r = run(&[
            mov64_imm(6, 100),
            st_mem(BPF_DW, BPF_REG_FP, -8, 1000),
            mov64_imm(1, 5),
            call_local(4),
            alu64_reg(BPF_ADD, 0, 6),
            ldx_mem(BPF_DW, 1, BPF_REG_FP, -8),
            alu64_reg(BPF_ADD, 0, 1),
            exit(),
            mov64_imm(6, 1),
            st_mem(BPF_DW, BPF_REG_FP, -8, 7),
            mov64_reg(0, 1),
            alu64_imm(BPF_MUL, 0, 2),
            ldx_mem(BPF_DW, 1, BPF_REG_FP, -8),
            alu64_reg(BPF_ADD, 0, 1),
            exit(),
        ]);
        // f gives 17, main keeps its R6 and its stack.
        assert_eq!(r, 17 + 100 + 1000);
        // f reads the stack of main through a pointer.
        let r = run(&[
            st_mem(BPF_DW, BPF_REG_FP, -8, 42),
            mov64_reg(1, BPF_REG_FP),
            alu64_imm(BPF_ADD, 1, -8),
            call_local(1),
            exit(),
            ldx_mem(BPF_DW, 0, 1, 0),
            exit(),
        ]);
        assert_eq!(r, 42);
    }

    #[test]
    fn packet_loads() {
        let ld = |p: &[BpfInsn]| {
            let mut insns = vec![mov64_reg(6, 1)];
            insns.extend_from_slice(p);
            run(&insns)
        };
        // The data is "abcdefgh", and the loads are in network byte order.
        assert_eq!(ld(&[ld_abs(BPF_B, 1), exit()]), u64::from(b'b'));
        assert_eq!(ld(&[ld_abs(BPF_H, 0), exit()]), 0x6162);
        assert_eq!(ld(&[ld_abs(BPF_W, 4), exit()]), 0x6566_6768);
        assert_eq!(ld(&[mov64_imm(2, 3), ld_ind(BPF_B, 2, 2), exit()]), u64::from(b'f'));
        assert_eq!(ld(&[ld_abs(BPF_B, -0x100000 + 2), exit()]), u64::from(b'c'));
        // A load out of the packet ends the program with 0.
        assert_eq!(ld(&[ld_abs(BPF_W, 6), mov64_imm(0, 9), exit()]), 0);
        assert_eq!(ld(&[ld_abs(BPF_B, -0x200000), mov64_imm(0, 9), exit()]), 0);
        assert_eq!(ld(&[mov64_imm(2, -1), ld_ind(BPF_B, 2, 0), mov64_imm(0, 9), exit()]), 0);
    }

    #[test]
    fn direct_loads_of_a_map_value() {
        let map = new_map(crate::uapi::map_type::BPF_MAP_TYPE_ARRAY, 8, 1);
        let [a, mut b] = ld_imm64(1, BPF_PSEUDO_MAP_VALUE, 0);
        b.imm = 4;
        let [c, d] = ld_imm64(2, BPF_PSEUDO_MAP_VALUE, 0);
        // Write 5 at byte 4 and read it through a second load of the value.
        let p = prog(
            &[a, b, st_mem(BPF_W, 1, 0, 5), c, d, ldx_mem(BPF_W, 0, 2, 4), exit()],
            vec![map.clone()],
        );
        let mut skb = SkBuff::default();
        assert_eq!(bpf_prog_run(&p, &mut skb, &NoEnv), Ok(5));
        let elem = map.ops.map_lookup_elem(&0u32.to_le_bytes()).unwrap();
        let mut v = [0u8; 4];
        elem.value(0).read(4, &mut v);
        assert_eq!(u32::from_le_bytes(v), 5);
    }

    fn new_map(map_type: u32, value_size: u32, max_entries: u32) -> Arc<BpfMap> {
        use crate::map::{MapAttr, map_alloc};
        let attr =
            MapAttr { map_type, key_size: 4, value_size, max_entries, map_flags: 0, numa_node: 0 };
        let ops = map_alloc(&attr, 1, u64::MAX).unwrap();
        Arc::new(BpfMap::new(&attr, [0; 16], 1, ops))
    }

    /// A tail call to the index `index` of the program array, the map 0 of the program. A
    /// failed tail call gives 7.
    fn tail_call_to(index: i32) -> Vec<BpfInsn> {
        let [a, b] = ld_imm64(2, BPF_PSEUDO_MAP_FD, 0);
        vec![a, b, mov64_imm(3, index), call(BPF_FUNC_tail_call), mov64_imm(0, 7), exit()]
    }

    #[test]
    fn a_tail_call_runs_the_program_of_the_slot() {
        use crate::uapi::map_type::BPF_MAP_TYPE_PROG_ARRAY;
        let pa = new_map(BPF_MAP_TYPE_PROG_ARRAY, 4, 2);
        let progs = pa.ops.as_prog_array().unwrap();
        let callee = Arc::new(prog(&[mov64_imm(0, 42), exit()], Vec::new()));
        progs.fd_update(&0u32.to_ne_bytes(), &[0; 4], 0, &|_| Ok(callee.clone())).unwrap();
        let mut skb = SkBuff::default();
        let mut go =
            |index| bpf_prog_run(&prog(&tail_call_to(index), vec![pa.clone()]), &mut skb, &NoEnv);
        assert_eq!(go(0), Ok(42));
        // An empty slot and an index out of the array continue after the call.
        assert_eq!(go(1), Ok(7));
        assert_eq!(go(2), Ok(7));
        assert_eq!(go(-1), Ok(7));
        progs.fd_update(&1u32.to_ne_bytes(), &[0; 4], 0, &|_| Ok(callee.clone())).unwrap();
        assert_eq!(go(1), Ok(42));
        pa.ops.map_release_uref();
        assert_eq!(go(0), Ok(7));
    }

    #[test]
    fn a_run_does_at_most_33_tail_calls() {
        use crate::uapi::map_type::{BPF_MAP_TYPE_ARRAY, BPF_MAP_TYPE_PROG_ARRAY};
        let pa = new_map(BPF_MAP_TYPE_PROG_ARRAY, 4, 1);
        let count = new_map(BPF_MAP_TYPE_ARRAY, 8, 1);
        // The program adds 1 to the value of the map 1 and does a tail call to itself.
        let [a, b] = ld_imm64(2, BPF_PSEUDO_MAP_VALUE, 1);
        let mut insns = vec![a, b, mov64_imm(3, 1), atomic(BPF_DW, 2, 3, 0, BPF_ADD as i32)];
        insns.extend(tail_call_to(0));
        let p = Arc::new(prog(&insns, vec![pa.clone(), count.clone()]));
        let progs = pa.ops.as_prog_array().unwrap();
        progs.fd_update(&0u32.to_ne_bytes(), &[0; 4], 0, &|_| Ok(p.clone())).unwrap();
        let mut skb = SkBuff::default();
        assert_eq!(bpf_prog_run(&p, &mut skb, &NoEnv), Ok(7));
        let elem = count.ops.map_lookup_elem(&0u32.to_ne_bytes()).unwrap();
        let mut v = [0u8; 8];
        elem.value(0).read(0, &mut v);
        // The first run and 33 tail calls.
        assert_eq!(u64::from_ne_bytes(v), 1 + u64::from(MAX_TAIL_CALL_CNT));
        pa.ops.map_release_uref();
    }
}
