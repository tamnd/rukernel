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

/// The state of one run.
struct Run<'a> {
    prog: &'a BpfProg,
    ctx: &'a mut dyn ProgCtx,
    env: &'a dyn HelperEnv,
    stack: Vec<u8>,
    values: Vec<Value>,
}

/// Runs `prog` with the context `ctx` and gives R0, as `bpf_prog_run` of Linux.
pub fn bpf_prog_run(prog: &BpfProg, ctx: &mut dyn ProgCtx, env: &dyn HelperEnv) -> Result<u64> {
    let mut run = Run { prog, ctx, env, stack: vec![0; MAX_BPF_STACK], values: Vec::new() };
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
    fn exec(&mut self) -> Result<u64> {
        let insns = &self.prog.insns;
        let mut regs = [0u64; MAX_BPF_REG];
        regs[1] = region_addr(REGION_CTX, 0);
        regs[BPF_REG_FP as usize] = region_addr(REGION_STACK, MAX_BPF_STACK as u32);
        let mut pc = 0usize;
        let mut steps = 0u64;
        loop {
            steps += 1;
            if steps > MAX_STEPS {
                return Err(Fault);
            }
            let insn = *insns.get(pc).ok_or(Fault)?;
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
                        BPF_EXIT => return Ok(regs[0]),
                        BPF_CALL if class == BPF_JMP && insn.src_reg == 0 => {
                            regs[0] = self.call(insn.imm, &regs)?;
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
                    let next = *insns.get(pc).ok_or(Fault)?;
                    pc += 1;
                    regs[d] = match insn.src_reg {
                        0 => u64::from(insn.imm as u32) | (u64::from(next.imm as u32) << 32),
                        BPF_PSEUDO_MAP_FD => map_addr(insn.imm as usize),
                        _ => return Err(Fault),
                    };
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
        let nmaps = self.prog.used_maps.len();
        match idx {
            REGION_STACK if end <= MAX_BPF_STACK => Ok(Loc::Stack(off)),
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

    /// The map of an argument.
    fn map_arg(&self, addr: u64) -> Result<Arc<BpfMap>> {
        match self.locate(addr, 0)? {
            Loc::Map(i) => Ok(self.prog.used_maps[i].clone()),
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
                        let idx = REGION_MAP0 + self.prog.used_maps.len() + self.values.len() - 1;
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
        let p = prog(&[ldx_mem(BPF_DW, 0, BPF_REG_FP, 0), exit()], Vec::new());
        let mut skb = SkBuff::default();
        assert_eq!(bpf_prog_run(&p, &mut skb, &NoEnv), Err(Fault));
    }
}
