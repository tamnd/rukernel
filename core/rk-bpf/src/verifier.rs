//! The verifier, kernel/bpf/verifier.c of Linux.
//!
//! The verifier accepts a program only when it can prove that each run of the program is safe:
//! each memory access is in bounds, each register is set before it is read, and the program
//! stops. This first verifier is smaller than the verifier of Linux, and it refuses what it
//! cannot prove:
//!
//! - `check_cfg` refuses back edges for a loader without `CAP_BPF`, and each instruction must be
//!   reachable. With `CAP_BPF`, `do_check` follows each round of a loop, so a loop must end
//!   within `BPF_COMPLEXITY_LIMIT_INSNS`.
//! - `do_check` follows each path of the program with the state of the registers and of the
//!   stack. It does not prune states, so the number of paths is limited by
//!   `BPF_COMPLEXITY_LIMIT_INSNS`.
//! - A scalar has a tnum and the unsigned and signed bounds. A pointer is to the context, to the
//!   stack, to a map, or to a map value that can be NULL until the program checks it.
//! - A call of a function of the program gets a new frame, and the verifier checks the function
//!   again at each call, as Linux does for a static function. Recursion stops at the limit of
//!   the frames.
//! - `BPF_LD_[ABS|IND]` and tail calls are allowed only in the main program, because rukernel
//!   has no BTF. Kernel functions and callbacks are refused.
//!
//! The messages of the log are the messages of Linux, so the tools that read them still work.
#![allow(non_upper_case_globals)]

use crate::helpers::func::BPF_FUNC_tail_call;
use crate::helpers::{ArgType, BpfFuncProto, RetType, get_func_proto};
use crate::insn::*;
use crate::map::BpfMap;
use crate::prog::prog_type::*;
use crate::prog::sk_buff;
use crate::tnum::{TNUM_UNKNOWN, Tnum};
use crate::uapi::attach_type::*;
use crate::uapi::flags::{BPF_F_RDONLY_PROG, BPF_F_WRONLY_PROG};
use crate::uapi::map_type::{BPF_MAP_TYPE_ARRAY, BPF_MAP_TYPE_PROG_ARRAY};
use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt::Write;
use rk_abi::Errno;

type Result<T> = core::result::Result<T, Errno>;

/// The log level that writes the errors and the statistics, `BPF_LOG_LEVEL1` of Linux.
pub const BPF_LOG_LEVEL1: u32 = 1;
/// The log level that writes each instruction, `BPF_LOG_LEVEL2` of Linux.
pub const BPF_LOG_LEVEL2: u32 = 2;
/// The log level that writes only the statistics, `BPF_LOG_STATS` of Linux.
pub const BPF_LOG_STATS: u32 = 4;
/// The log keeps the start of the text, not the end, `BPF_LOG_FIXED` of Linux.
pub const BPF_LOG_FIXED: u32 = 8;
/// The bits of a valid log level, `BPF_LOG_MASK` of Linux.
pub const BPF_LOG_MASK: u32 = BPF_LOG_LEVEL1 | BPF_LOG_LEVEL2 | BPF_LOG_STATS | BPF_LOG_FIXED;

/// The most states that wait to be checked, `BPF_COMPLEXITY_LIMIT_JMP_SEQ` of Linux.
const BPF_COMPLEXITY_LIMIT_JMP_SEQ: usize = 8192;
/// The most states that `do_check` keeps for the pruning. A state is about 5 KiB.
const MAX_KEPT_STATES: usize = 1024;
/// The most states that `do_check` keeps for one instruction. The states of a loop are all
/// different, and each round compares the state with each kept state.
const MAX_KEPT_STATES_PER_INSN: usize = 16;
/// The largest offset of a pointer, `BPF_MAX_VAR_OFF` of Linux.
const BPF_MAX_VAR_OFF: i64 = 1 << 29;

/// The text of the log of the verifier, `struct bpf_verifier_log` of Linux. The system call
/// copies the text to the buffer of the program.
#[derive(Debug, Default)]
pub struct BpfVerifierLog {
    /// The log level.
    pub level: u32,
    /// The text.
    pub text: String,
}

impl BpfVerifierLog {
    /// A log with the level `level`.
    pub fn new(level: u32) -> Self {
        Self { level, text: String::new() }
    }

    /// Adds text to the log, as `bpf_verifier_log_write` of Linux.
    pub fn write(&mut self, args: core::fmt::Arguments<'_>) {
        if self.level != 0 {
            let _ = self.text.write_fmt(args);
        }
    }
}

macro_rules! verbose {
    ($env:expr, $($arg:tt)*) => {
        $env.log.write(format_args!($($arg)*))
    };
}

/// The type of a register, `enum bpf_reg_type` of Linux.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RegType {
    NotInit,
    Scalar,
    PtrToCtx,
    ConstPtrToMap,
    PtrToMapValue,
    PtrToMapValueOrNull,
    PtrToStack,
}

/// The name of a type in the log, `reg_type_str` of Linux.
fn reg_type_str(t: RegType) -> &'static str {
    match t {
        RegType::NotInit => "?",
        RegType::Scalar => "scalar",
        RegType::PtrToCtx => "ctx",
        RegType::ConstPtrToMap => "map_ptr",
        RegType::PtrToMapValue => "map_value",
        RegType::PtrToMapValueOrNull => "map_value_or_null",
        RegType::PtrToStack => "fp",
    }
}

/// The state of a register, `struct bpf_reg_state` of Linux. For a scalar, `var` and the bounds
/// are the value. For a pointer, `off` is the fixed offset, and `var` and the bounds are the
/// variable offset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Reg {
    ty: RegType,
    off: i32,
    var: Tnum,
    umin: u64,
    umax: u64,
    smin: i64,
    smax: i64,
    /// The index of the map in `used_maps`.
    map: usize,
    /// The ID that the NULL check uses.
    id: u32,
    /// The frame of a pointer to the stack, 0 for the main program.
    frameno: u32,
}

impl Reg {
    const NOT_INIT: Reg = Reg {
        ty: RegType::NotInit,
        off: 0,
        var: TNUM_UNKNOWN,
        umin: 0,
        umax: u64::MAX,
        smin: i64::MIN,
        smax: i64::MAX,
        map: 0,
        id: 0,
        frameno: 0,
    };

    /// An unknown scalar, `mark_reg_unknown` of Linux.
    fn unknown() -> Reg {
        Reg { ty: RegType::Scalar, ..Reg::NOT_INIT }
    }

    /// A known scalar, `__mark_reg_known` of Linux.
    fn known(v: u64) -> Reg {
        Reg {
            var: Tnum::constant(v),
            umin: v,
            umax: v,
            smin: v as i64,
            smax: v as i64,
            ..Reg::unknown()
        }
    }

    /// A scalar with the bounds of the tnum `var`.
    fn from_tnum(var: Tnum) -> Reg {
        let mut r = Reg { var, ..Reg::unknown() };
        r.bounds_sync();
        r
    }

    /// An unknown scalar of `size` bytes, as `coerce_reg_to_size` of Linux.
    fn unknown_of_size(size: u32) -> Reg {
        if size >= 8 { Reg::unknown() } else { Reg::from_tnum(TNUM_UNKNOWN.cast(size)) }
    }

    /// A pointer with the offset 0.
    fn ptr(ty: RegType) -> Reg {
        Reg { ty, ..Reg::known(0) }
    }

    fn is_pointer(&self) -> bool {
        !matches!(self.ty, RegType::Scalar | RegType::NotInit)
    }

    fn is_const(&self) -> bool {
        self.ty == RegType::Scalar && self.var.is_const()
    }

    /// Updates the bounds from each other, as `reg_bounds_sync` of Linux. Gives false when no
    /// value fits the bounds.
    fn bounds_sync(&mut self) -> bool {
        for _ in 0..2 {
            self.umin = self.umin.max(self.var.min());
            self.umax = self.umax.min(self.var.max());
            if (self.umin as i64) <= (self.umax as i64) {
                // The unsigned range does not cross the sign bit.
                self.smin = self.smin.max(self.umin as i64);
                self.smax = self.smax.min(self.umax as i64);
            }
            if self.smin >= 0 || self.smax < 0 {
                self.umin = self.umin.max(self.smin as u64);
                self.umax = self.umax.min(self.smax as u64);
            }
            if self.umin > self.umax || self.smin > self.smax {
                return false;
            }
            self.var = self.var.intersect(Tnum::range(self.umin, self.umax));
        }
        true
    }

    /// Forgets the signed bounds, and finds them again from the other bounds.
    fn with_unknown_signed(mut self) -> Reg {
        self.smin = i64::MIN;
        self.smax = i64::MAX;
        self.bounds_sync();
        self
    }
}

/// One slot of 8 bytes of the stack, `struct bpf_stack_state` of Linux.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct StackSlot {
    /// The bytes: `STACK_INVALID`, `STACK_MISC` or `STACK_SPILL`.
    slot_type: [u8; 8],
    /// The register that the program spilled to the slot.
    spilled: Reg,
}

const STACK_INVALID: u8 = 0;
const STACK_MISC: u8 = 1;
const STACK_SPILL: u8 = 2;
const SLOTS: usize = MAX_BPF_STACK / 8;

impl StackSlot {
    const EMPTY: StackSlot = StackSlot { slot_type: [STACK_INVALID; 8], spilled: Reg::NOT_INIT };

    fn is_spill(&self) -> bool {
        self.slot_type[0] == STACK_SPILL
    }
}

/// The state of a path, `struct bpf_verifier_state` of Linux. `regs` and `stack` are of the
/// frame that runs now. The registers and the stack are on the heap, because the kernel stack
/// is small. A debug build keeps many copies of a state on the stack when the state is large.
#[derive(Clone, Debug, PartialEq, Eq)]
struct State {
    regs: Box<[Reg; MAX_BPF_REG]>,
    /// The slots of the stack.
    stack: Vec<StackSlot>,
    /// The function of the program that runs now.
    subprog: usize,
    /// The frames of the callers, the main program first.
    callers: Vec<Frame>,
}

/// The state of a caller, `struct bpf_func_state` of Linux.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Frame {
    regs: Box<[Reg; MAX_BPF_REG]>,
    stack: Vec<StackSlot>,
    subprog: usize,
    /// The instruction of the call.
    callsite: usize,
}

impl State {
    /// The number of the frame that runs now, `curframe` of Linux.
    fn curframe(&self) -> u32 {
        self.callers.len() as u32
    }

    /// The stack of the frame `frameno`.
    fn stack_of(&mut self, frameno: u32) -> &mut Vec<StackSlot> {
        match self.callers.get_mut(frameno as usize) {
            Some(f) => &mut f.stack,
            None => &mut self.stack,
        }
    }

    /// The function of the program of the frame `frameno`.
    fn subprog_of(&self, frameno: u32) -> usize {
        self.callers.get(frameno as usize).map_or(self.subprog, |f| f.subprog)
    }
}

/// A function of the program, `struct bpf_subprog_info` of Linux.
#[derive(Clone, Copy, Debug, Default)]
struct Subprog {
    /// The first instruction.
    start: usize,
    /// The bytes of the stack that the function uses.
    stack_depth: u32,
    has_tail_call: bool,
    has_ld_abs: bool,
}

/// The most functions of a program, `BPF_MAX_SUBPROGS` of Linux.
const BPF_MAX_SUBPROGS: usize = 256;
/// The most maps of a program, `MAX_USED_MAPS` of Linux.
const MAX_USED_MAPS: usize = 64;
/// `ENOTSUPP` of include/linux/errno.h. Linux gives this number of the kernel to user space
/// when the kernel cannot call a kernel function.
const ENOTSUPP: Errno = Errno::ENOTSUPP;

/// Shows a tnum as `tnum_strn` of Linux, which prints with `%#llx`: 0 is `0`, and other numbers
/// have `0x`.
struct TnumStr(Tnum);

impl core::fmt::Display for TnumStr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let hex = |f: &mut core::fmt::Formatter<'_>, v: u64| {
            if v == 0 { f.write_str("0") } else { write!(f, "{v:#x}") }
        };
        f.write_str("(")?;
        hex(f, self.0.value)?;
        f.write_str("; ")?;
        hex(f, self.0.mask)?;
        f.write_str(")")
    }
}

/// The verifier, `struct bpf_verifier_env` of Linux.
struct Env<'a> {
    insns: &'a [BpfInsn],
    maps: &'a [Arc<BpfMap>],
    prog_type: u32,
    expected_attach_type: u32,
    bpf_capable: bool,
    allow_ptr_leaks: bool,
    /// The loader gave `BPF_F_STRICT_ALIGNMENT`, `strict_alignment` of Linux.
    strict_alignment: bool,
    /// The access of an atomic instruction must be aligned, `strict_alignment_once` of Linux.
    strict_once: bool,
    log: &'a mut BpfVerifierLog,
    enforce_expected_attach_type: bool,
    id_gen: u32,
    insn_processed: u32,
    /// The functions of the program, ordered by their first instruction.
    subprogs: Vec<Subprog>,
    /// The type of the pointer of each load or store, `insn_aux_data[].ptr_type` of Linux.
    ptr_types: Vec<RegType>,
}

/// What the program does with a memory access.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Access {
    Read,
    Write,
}

/// The result of `bpf_check`.
pub struct Verified {
    /// The instructions. Each `BPF_PSEUDO_MAP_FD` load has the index of its map.
    pub insns: Vec<BpfInsn>,
    /// The maps of the program, `used_maps` of Linux.
    pub used_maps: Vec<Arc<BpfMap>>,
    /// The number of instructions that the verifier looked at, `insn_processed` of Linux.
    pub insn_processed: u32,
    /// The program can attach only at its expected attach type.
    pub enforce_expected_attach_type: bool,
}

/// What the verifier needs of the loader.
pub struct VerifierOpts {
    /// The type of the program.
    pub prog_type: u32,
    /// The attach type that the program expects.
    pub expected_attach_type: u32,
    /// The loader has `CAP_BPF` or `CAP_SYS_ADMIN`.
    pub bpf_capable: bool,
    /// The loader has `CAP_PERFMON`, so a program can show addresses, `allow_ptr_leaks` of Linux.
    pub allow_ptr_leaks: bool,
    /// Each access of memory must be aligned to its size, as `BPF_F_STRICT_ALIGNMENT`. x86_64
    /// and arm64 have efficient unaligned access, so this is false without the flag.
    pub strict_alignment: bool,
}

/// Tells if the verifier knows the program type, as `find_prog_type` of Linux.
pub fn prog_type_known(prog_type: u32) -> bool {
    matches!(
        prog_type,
        BPF_PROG_TYPE_SOCKET_FILTER
            | BPF_PROG_TYPE_CGROUP_SKB
            | BPF_PROG_TYPE_CGROUP_SOCK
            | BPF_PROG_TYPE_CGROUP_SOCK_ADDR
            | BPF_PROG_TYPE_CGROUP_DEVICE
    )
}

/// Checks the program, as `bpf_check` of Linux. `map_by_fd` gives the map of a file
/// descriptor. `fd_array` gives the descriptor at an index of the `fd_array` of the loader, if
/// the loader gave one. The messages go to `log`.
pub fn bpf_check(
    mut insns: Vec<BpfInsn>,
    opts: &VerifierOpts,
    map_by_fd: &dyn Fn(i32) -> Result<Arc<BpfMap>>,
    fd_array: Option<&dyn Fn(u32) -> Result<i32>>,
    log: &mut BpfVerifierLog,
) -> Result<Verified> {
    let (r, subprogs) = {
        let mut env = Env {
            insns: &insns,
            maps: &[],
            prog_type: opts.prog_type,
            expected_attach_type: opts.expected_attach_type,
            bpf_capable: opts.bpf_capable,
            allow_ptr_leaks: opts.allow_ptr_leaks,
            strict_alignment: opts.strict_alignment,
            strict_once: false,
            log: &mut *log,
            enforce_expected_attach_type: false,
            id_gen: 0,
            insn_processed: 0,
            subprogs: Vec::new(),
            ptr_types: Vec::new(),
        };
        let r = env
            .add_subprogs()
            .and_then(|()| env.check_subprogs())
            .and_then(|()| env.check_abnormal_return());
        (r, env.subprogs)
    };
    let used_maps =
        match r.and_then(|()| resolve_pseudo_ldimm64(&mut insns, map_by_fd, fd_array, log)) {
            Ok(m) => m,
            Err(e) => {
                print_verification_stats(log, 0);
                return Err(e);
            }
        };
    let mut env = Env {
        insns: &insns,
        maps: &used_maps,
        prog_type: opts.prog_type,
        expected_attach_type: opts.expected_attach_type,
        bpf_capable: opts.bpf_capable,
        allow_ptr_leaks: opts.allow_ptr_leaks,
        strict_alignment: opts.strict_alignment,
        strict_once: false,
        log,
        enforce_expected_attach_type: false,
        id_gen: 0,
        insn_processed: 0,
        subprogs,
        ptr_types: vec![RegType::NotInit; insns.len()],
    };
    let r = env
        .check_cfg()
        .and_then(|()| env.do_check())
        .and_then(|()| env.check_max_stack_depth())
        .and_then(|()| env.fixup_call_args());
    print_verification_stats(env.log, env.insn_processed);
    r?;
    let insn_processed = env.insn_processed;
    let enforce_expected_attach_type = env.enforce_expected_attach_type;
    Ok(Verified { insns, used_maps, insn_processed, enforce_expected_attach_type })
}

/// The last line of the log, `print_verification_stats` of Linux.
fn print_verification_stats(log: &mut BpfVerifierLog, insn_processed: u32) {
    log.write(format_args!(
        "processed {} insns (limit {}) max_states_per_insn 0 total_states 0 peak_states 0 \
         mark_read 0\n",
        insn_processed, BPF_COMPLEXITY_LIMIT_INSNS
    ));
}

/// Tells if the opcode is an instruction of RFC 9669, as `bpf_opcode_in_insntable` of Linux.
fn bpf_opcode_in_insntable(code: u8) -> bool {
    match bpf_class(code) {
        BPF_ALU | BPF_ALU64 => {
            let op = bpf_op(code);
            if op == BPF_END {
                return bpf_class(code) == BPF_ALU || bpf_src(code) == BPF_K;
            }
            op <= BPF_ARSH && (op != BPF_NEG || bpf_src(code) == BPF_K)
        }
        BPF_JMP | BPF_JMP32 => {
            let op = bpf_op(code);
            if op == BPF_CALL || op == BPF_EXIT {
                return bpf_class(code) == BPF_JMP && bpf_src(code) == BPF_K;
            }
            if op == BPF_JA {
                return bpf_src(code) == BPF_K;
            }
            op <= BPF_JSLE
        }
        BPF_LDX => {
            matches!(bpf_mode(code), BPF_MEM | BPF_MEMSX)
                && !(bpf_mode(code) == BPF_MEMSX && bpf_size(code) == BPF_DW)
        }
        BPF_ST => bpf_mode(code) == BPF_MEM,
        BPF_STX => {
            matches!(bpf_mode(code), BPF_MEM)
                || (bpf_mode(code) == BPF_ATOMIC && matches!(bpf_size(code), BPF_W | BPF_DW))
        }
        BPF_LD => {
            code == BPF_LD | BPF_IMM | BPF_DW
                || (matches!(bpf_mode(code), BPF_ABS | BPF_IND) && bpf_size(code) != BPF_DW)
        }
        _ => false,
    }
}

/// Checks the opcodes and puts the maps of the 64-bit loads in `used_maps`, as
/// `resolve_pseudo_ldimm64` of Linux. A load of a map gets the index of the map in
/// `used_maps`. A load with the map as an index in `fd_array` becomes a load with
/// `BPF_PSEUDO_MAP_FD` or `BPF_PSEUDO_MAP_VALUE`.
fn resolve_pseudo_ldimm64(
    insns: &mut [BpfInsn],
    map_by_fd: &dyn Fn(i32) -> Result<Arc<BpfMap>>,
    fd_array: Option<&dyn Fn(u32) -> Result<i32>>,
    log: &mut BpfVerifierLog,
) -> Result<Vec<Arc<BpfMap>>> {
    let mut used: Vec<Arc<BpfMap>> = Vec::new();
    let n = insns.len();
    let mut i = 0;
    while i < n {
        let insn = insns[i];
        if bpf_class(insn.code) == BPF_LDX
            && (!matches!(bpf_mode(insn.code), BPF_MEM | BPF_MEMSX) || insn.imm != 0)
        {
            log.write(format_args!("BPF_LDX uses reserved fields\n"));
            return Err(Errno::EINVAL);
        }
        if insn.is_ld_imm64() {
            if i == n - 1
                || insns[i + 1].code != 0
                || insns[i + 1].dst_reg != 0
                || insns[i + 1].src_reg != 0
                || insns[i + 1].off != 0
            {
                log.write(format_args!("invalid bpf_ld_imm64 insn\n"));
                return Err(Errno::EINVAL);
            }
            let src = insn.src_reg;
            let ok = match src {
                0 => {
                    i += 2;
                    continue;
                }
                BPF_PSEUDO_MAP_VALUE | BPF_PSEUDO_MAP_IDX_VALUE => true,
                BPF_PSEUDO_MAP_FD | BPF_PSEUDO_MAP_IDX => insns[i + 1].imm == 0,
                _ => false,
            };
            if !ok {
                log.write(format_args!("unrecognized bpf_ld_imm64 insn\n"));
                return Err(Errno::EINVAL);
            }
            let fd = if matches!(src, BPF_PSEUDO_MAP_IDX | BPF_PSEUDO_MAP_IDX_VALUE) {
                let Some(fd_array) = fd_array else {
                    log.write(format_args!("fd_idx without fd_array is invalid\n"));
                    return Err(Errno::EPROTO);
                };
                fd_array(insn.imm as u32)?
            } else {
                insn.imm
            };
            let map = map_by_fd(fd).inspect_err(|_| {
                log.write(format_args!("fd {fd} is not pointing to valid bpf_map\n"));
            })?;
            // Two loads of one map use one entry of `used_maps`, as `__add_used_map`.
            let idx = match used.iter().position(|m| Arc::ptr_eq(m, &map)) {
                Some(idx) => idx,
                None => {
                    if used.len() >= MAX_USED_MAPS {
                        log.write(format_args!(
                            "The total number of maps per program has reached the limit of {}\n",
                            MAX_USED_MAPS
                        ));
                        return Err(Errno::E2BIG);
                    }
                    used.push(map.clone());
                    used.len() - 1
                }
            };
            if matches!(src, BPF_PSEUDO_MAP_VALUE | BPF_PSEUDO_MAP_IDX_VALUE) {
                let off = insns[i + 1].imm as u32;
                if i64::from(off) >= BPF_MAX_VAR_OFF {
                    log.write(format_args!("direct value offset of {off} is not allowed\n"));
                    return Err(Errno::EINVAL);
                }
                // `array_map_direct_value_addr`: only an array of one value has a fixed
                // address.
                if map.map_type != BPF_MAP_TYPE_ARRAY {
                    log.write(format_args!("no direct value access support for this map type\n"));
                    return Err(Errno::EINVAL);
                }
                let err = if map.max_entries != 1 {
                    Some(Errno::EOPNOTSUPP)
                } else if off >= map.value_size {
                    Some(Errno::EINVAL)
                } else {
                    None
                };
                if let Some(e) = err {
                    log.write(format_args!(
                        "invalid access to map value pointer, value_size={} off={}\n",
                        map.value_size, off
                    ));
                    return Err(e);
                }
                insns[i].src_reg = BPF_PSEUDO_MAP_VALUE;
            } else {
                insns[i].src_reg = BPF_PSEUDO_MAP_FD;
            }
            insns[i].imm = idx as i32;
            i += 2;
            continue;
        }
        if !bpf_opcode_in_insntable(insn.code) {
            log.write(format_args!("unknown opcode {:02x}\n", insn.code));
            return Err(Errno::EINVAL);
        }
        i += 1;
    }
    Ok(used)
}

/// The successors of the instruction `i`, as `visit_insn` of Linux. `None` is the end of the
/// program.
fn successors(insns: &[BpfInsn], i: usize) -> [Option<i64>; 2] {
    let insn = insns[i];
    let next = if insn.is_ld_imm64() { i as i64 + 2 } else { i as i64 + 1 };
    let class = bpf_class(insn.code);
    if class != BPF_JMP && class != BPF_JMP32 {
        return [Some(next), None];
    }
    match bpf_op(insn.code) {
        BPF_EXIT => [None, None],
        // `visit_func_call_insn`: a call of a function of the program goes on after the call
        // and in the function.
        BPF_CALL if insn.src_reg == BPF_PSEUDO_CALL => {
            [Some(next), Some(i as i64 + 1 + insn.imm as i64)]
        }
        BPF_CALL => [Some(next), None],
        BPF_JA => {
            let off = if class == BPF_JMP32 { insn.imm as i64 } else { insn.off as i64 };
            [Some(i as i64 + 1 + off), None]
        }
        _ => [Some(next), Some(i as i64 + 1 + insn.off as i64)],
    }
}

impl Env<'_> {
    /// Finds the functions of the program, as `add_subprog_and_kfunc` of Linux.
    fn add_subprogs(&mut self) -> Result<()> {
        self.subprogs = vec![Subprog::default()];
        let insns = self.insns;
        for (i, insn) in insns.iter().enumerate() {
            let call = insn.code == BPF_JMP | BPF_CALL
                && matches!(insn.src_reg, BPF_PSEUDO_CALL | BPF_PSEUDO_KFUNC_CALL);
            let func = insn.is_ld_imm64() && insn.src_reg == BPF_PSEUDO_FUNC;
            if !call && !func {
                continue;
            }
            if !self.bpf_capable {
                verbose!(
                    self,
                    "loading/calling other bpf or kernel functions are allowed for CAP_BPF and \
                     CAP_SYS_ADMIN\n"
                );
                return Err(Errno::EPERM);
            }
            if call && insn.src_reg == BPF_PSEUDO_KFUNC_CALL {
                // `add_kfunc_call`: rukernel has no BTF of the kernel.
                verbose!(
                    self,
                    "calling kernel function is not supported without CONFIG_DEBUG_INFO_BTF\n"
                );
                return Err(ENOTSUPP);
            }
            self.add_subprog(i as i64 + insn.imm as i64 + 1)?;
        }
        if self.log.level & BPF_LOG_LEVEL2 != 0 {
            for (i, sp) in self.subprogs.iter().enumerate() {
                self.log.write(format_args!("func#{} @{}\n", i, sp.start));
            }
        }
        Ok(())
    }

    /// `add_subprog` of Linux.
    fn add_subprog(&mut self, off: i64) -> Result<()> {
        if off < 0 || off >= self.insns.len() as i64 {
            verbose!(self, "call to invalid destination\n");
            return Err(Errno::EINVAL);
        }
        let off = off as usize;
        let Err(at) = self.subprogs.binary_search_by_key(&off, |sp| sp.start) else {
            return Ok(());
        };
        if self.subprogs.len() >= BPF_MAX_SUBPROGS {
            verbose!(self, "too many subprograms\n");
            return Err(Errno::E2BIG);
        }
        self.subprogs.insert(at, Subprog { start: off, ..Subprog::default() });
        Ok(())
    }

    /// The instruction after the last one of the function `idx`.
    fn subprog_end(&self, idx: usize) -> usize {
        self.subprogs.get(idx + 1).map_or(self.insns.len(), |sp| sp.start)
    }

    /// The function that starts at `off`, `find_subprog` of Linux.
    fn find_subprog(&self, off: usize) -> Option<usize> {
        self.subprogs.binary_search_by_key(&off, |sp| sp.start).ok()
    }

    /// Checks that each jump stays in its function and that each function ends with an exit or
    /// a jump, as `check_subprogs` of Linux.
    fn check_subprogs(&mut self) -> Result<()> {
        let insns = self.insns;
        let mut cur = 0;
        let mut start = 0;
        let mut end = self.subprog_end(0);
        for (i, insn) in insns.iter().enumerate() {
            let code = insn.code;
            let class = bpf_class(code);
            if code == BPF_JMP | BPF_CALL && insn.src_reg == 0 && insn.imm == BPF_FUNC_tail_call {
                self.subprogs[cur].has_tail_call = true;
            }
            if class == BPF_LD && matches!(bpf_mode(code), BPF_ABS | BPF_IND) {
                self.subprogs[cur].has_ld_abs = true;
            }
            if (class == BPF_JMP || class == BPF_JMP32)
                && !matches!(bpf_op(code), BPF_CALL | BPF_EXIT)
            {
                let off =
                    if code == BPF_JMP32 | BPF_JA { insn.imm as i64 } else { insn.off as i64 };
                let target = i as i64 + off + 1;
                if target < start as i64 || target >= end as i64 {
                    verbose!(self, "jump out of range from insn {} to {}\n", i, target);
                    return Err(Errno::EINVAL);
                }
            }
            if i == end - 1 {
                let last_ok = code == BPF_JMP | BPF_EXIT
                    || code == BPF_JMP32 | BPF_JA
                    || code == BPF_JMP | BPF_JA;
                if !last_ok {
                    verbose!(self, "last insn is not an exit or jmp\n");
                    return Err(Errno::EINVAL);
                }
                start = end;
                cur += 1;
                end = self.subprog_end(cur);
            }
        }
        Ok(())
    }

    /// Refuses `BPF_LD_[ABS|IND]` and tail calls in a function that is not the main program,
    /// as `check_abnormal_return` of Linux. Linux allows them only with BTF, which rukernel
    /// does not have. It also refuses callbacks, as `fixup_call_args` of Linux without a JIT.
    fn check_abnormal_return(&mut self) -> Result<()> {
        for i in 1..self.subprogs.len() {
            if self.subprogs[i].has_ld_abs {
                verbose!(self, "LD_ABS is not allowed in subprogs without BTF\n");
                return Err(Errno::EINVAL);
            }
            if self.subprogs[i].has_tail_call {
                verbose!(self, "tail_call is not allowed in subprogs without BTF\n");
                return Err(Errno::EINVAL);
            }
        }
        if self.insns.iter().any(|i| i.is_ld_imm64() && i.src_reg == BPF_PSEUDO_FUNC) {
            verbose!(self, "callbacks are not allowed in non-JITed programs\n");
            return Err(Errno::EINVAL);
        }
        Ok(())
    }

    /// The checks of `fixup_call_args` of Linux without a JIT: the interpreter cannot run a
    /// tail call in a program with functions.
    fn fixup_call_args(&mut self) -> Result<()> {
        if self.subprogs.len() > 1 && self.subprogs[0].has_tail_call {
            verbose!(
                self,
                "tail_calls are not allowed in non-JITed programs with bpf-to-bpf calls\n"
            );
            return Err(Errno::EINVAL);
        }
        Ok(())
    }

    /// Checks the stack of each chain of calls, as `check_max_stack_depth` of Linux. The
    /// interpreter rounds the stack of each function up to 32 bytes.
    fn check_max_stack_depth(&mut self) -> Result<()> {
        let round = |d: u32| d.max(1).next_multiple_of(32);
        let insns = self.insns;
        let mut ret_insn = [0usize; MAX_CALL_FRAMES];
        let mut ret_prog = [0usize; MAX_CALL_FRAMES];
        let (mut depth, mut frame, mut idx, mut i) = (0u32, 0usize, 0usize, 0usize);
        let mut enter = true;
        loop {
            if enter {
                depth += round(self.subprogs[idx].stack_depth);
                if depth > MAX_BPF_STACK as u32 {
                    verbose!(
                        self,
                        "combined stack size of {} calls is {}. Too large\n",
                        frame + 1,
                        depth
                    );
                    return Err(Errno::EACCES);
                }
            }
            enter = false;
            let end = self.subprog_end(idx);
            while i < end {
                let insn = insns[i];
                if insn.code == BPF_JMP | BPF_CALL && insn.src_reg == BPF_PSEUDO_CALL {
                    ret_insn[frame] = i + 1;
                    ret_prog[frame] = idx;
                    let next = (i as i64 + insn.imm as i64 + 1) as usize;
                    idx = self.find_subprog(next).ok_or(Errno::EFAULT)?;
                    i = next;
                    frame += 1;
                    if frame >= MAX_CALL_FRAMES {
                        verbose!(self, "the call stack of {} frames is too deep !\n", frame);
                        return Err(Errno::E2BIG);
                    }
                    enter = true;
                    break;
                }
                i += 1;
            }
            if enter {
                continue;
            }
            if frame == 0 {
                return Ok(());
            }
            depth -= round(self.subprogs[idx].stack_depth);
            frame -= 1;
            i = ret_insn[frame];
            idx = ret_prog[frame];
        }
    }

    /// Notes that the function `subprog` uses `size` bytes of its stack, as
    /// `grow_stack_state` of Linux.
    fn grow_stack(&mut self, subprog: usize, size: i64) {
        let size = (size.max(0) as u32).next_multiple_of(8);
        let sp = &mut self.subprogs[subprog];
        sp.stack_depth = sp.stack_depth.max(size);
    }

    /// Refuses loops and dead code, as `check_cfg` of Linux.
    fn check_cfg(&mut self) -> Result<()> {
        const DISCOVERED: u8 = 1;
        const EXPLORED: u8 = 2;
        let n = self.insns.len();
        // The second halves of the 64-bit loads.
        let mut half = vec![false; n];
        let mut i = 0;
        while i < n {
            if self.insns[i].is_ld_imm64() {
                half[i + 1] = true;
                i += 2;
            } else {
                i += 1;
            }
        }
        let mut state = vec![0u8; n];
        let mut stack: Vec<(usize, usize)> = vec![(0, 0)];
        state[0] = DISCOVERED;
        while let Some(&mut (t, ref mut k)) = stack.last_mut() {
            let succ = successors(self.insns, t);
            if *k < 2 {
                let s = succ[*k];
                *k += 1;
                let Some(w) = s else { continue };
                if w < 0 || w >= n as i64 {
                    verbose!(self, "jump out of range from insn {} to {}\n", t, w);
                    return Err(Errno::EINVAL);
                }
                let w = w as usize;
                if half[w] {
                    verbose!(self, "jump into the middle of ldimm64 insn {}\n", w - 1);
                    return Err(Errno::EINVAL);
                }
                match state[w] {
                    0 => {
                        state[w] = DISCOVERED;
                        stack.push((w, 0));
                    }
                    // A loader with `CAP_BPF` can have loops. `do_check` follows each round of a
                    // loop, and refuses a loop that does not end within
                    // `BPF_COMPLEXITY_LIMIT_INSNS`.
                    DISCOVERED if self.bpf_capable => {}
                    DISCOVERED => {
                        verbose!(self, "back-edge from insn {} to {}\n", t, w);
                        return Err(Errno::EINVAL);
                    }
                    _ => {}
                }
            } else {
                state[t] = EXPLORED;
                stack.pop();
            }
        }
        for i in 0..n {
            if state[i] != EXPLORED && !half[i] {
                verbose!(self, "unreachable insn {}\n", i);
                return Err(Errno::EINVAL);
            }
        }
        Ok(())
    }

    /// Follows each path of the program, as `do_check` of Linux.
    fn do_check(&mut self) -> Result<()> {
        let mut regs = Box::new([Reg::NOT_INIT; MAX_BPF_REG]);
        regs[1] = Reg::ptr(RegType::PtrToCtx);
        regs[BPF_REG_FP as usize] = Reg::ptr(RegType::PtrToStack);
        let st =
            State { regs, stack: vec![StackSlot::EMPTY; SLOTS], subprog: 0, callers: Vec::new() };
        // The pruning of `is_state_visited` of Linux, with states that are equal. A state that
        // is equal to a state of the same instruction gives the same result, so the path stops.
        // When the earlier state is on the current path, the path is a loop that does not end.
        // A path that waits in `pending` remembers the length of `path` when it starts, because
        // the states after that length are of a branch that is complete when it starts.
        let prune = self.prune_points();
        let mut kept: Vec<Vec<(State, bool)>> = vec![Vec::new(); self.insns.len()];
        let mut nkept = 0;
        let mut path: Vec<(usize, usize)> = Vec::new();
        let mut pending: Vec<(usize, State, usize)> = vec![(0, st, 0)];
        while let Some((mut pc, mut st, depth)) = pending.pop() {
            for (p, i) in path.drain(depth..) {
                kept[p][i].1 = false;
            }
            loop {
                if prune[pc] {
                    if let Some(&(_, on_path)) = kept[pc].iter().find(|(s, _)| *s == st) {
                        if on_path {
                            verbose!(self, "infinite loop detected at insn {}\n", pc);
                            return Err(Errno::EINVAL);
                        }
                        break;
                    }
                    if nkept < MAX_KEPT_STATES && kept[pc].len() < MAX_KEPT_STATES_PER_INSN {
                        kept[pc].push((st.clone(), true));
                        path.push((pc, kept[pc].len() - 1));
                        nkept += 1;
                    }
                }
                self.insn_processed += 1;
                if self.insn_processed > BPF_COMPLEXITY_LIMIT_INSNS {
                    verbose!(
                        self,
                        "BPF program is too large. Processed {} insn\n",
                        self.insn_processed
                    );
                    return Err(Errno::E2BIG);
                }
                if self.log.level & BPF_LOG_LEVEL2 != 0 {
                    verbose!(self, "{}: (code {:02x})\n", pc, self.insns[pc].code);
                }
                match self.do_insn(pc, &mut st)? {
                    Next::Go(next) => pc = next,
                    Next::Branch(next, other, other_state) => {
                        if pending.len() >= BPF_COMPLEXITY_LIMIT_JMP_SEQ {
                            verbose!(
                                self,
                                "The sequence of {} jumps is too complex.\n",
                                pending.len()
                            );
                            return Err(Errno::E2BIG);
                        }
                        pending.push((other, *other_state, path.len()));
                        pc = next;
                    }
                    Next::Exit => break,
                }
            }
        }
        Ok(())
    }

    /// The instructions where `do_check` compares the states, as `mark_prune_point` of Linux:
    /// the targets of the jumps and the instructions after the conditional jumps.
    fn prune_points(&self) -> Vec<bool> {
        let n = self.insns.len();
        let mut prune = vec![false; n];
        for i in 0..n {
            let class = bpf_class(self.insns[i].code);
            if (class != BPF_JMP && class != BPF_JMP32)
                || matches!(bpf_op(self.insns[i].code), BPF_EXIT | BPF_CALL)
            {
                continue;
            }
            for w in successors(self.insns, i).into_iter().flatten() {
                if (0..n as i64).contains(&w) {
                    prune[w as usize] = true;
                }
            }
        }
        prune
    }

    /// Reads a register, as `check_reg_arg` with `SRC_OP` of Linux.
    fn read_reg(&mut self, st: &State, regno: u8) -> Result<Reg> {
        self.check_regno(regno)?;
        let r = st.regs[regno as usize];
        if r.ty == RegType::NotInit {
            verbose!(self, "R{} !read_ok\n", regno);
            return Err(Errno::EACCES);
        }
        Ok(r)
    }

    /// Checks that a register can be written, as `check_reg_arg` with `DST_OP` of Linux.
    fn check_dst(&mut self, regno: u8) -> Result<()> {
        self.check_regno(regno)?;
        if regno == BPF_REG_FP {
            verbose!(self, "frame pointer is read only\n");
            return Err(Errno::EACCES);
        }
        Ok(())
    }

    /// The first check of `check_reg_arg` of Linux.
    fn check_regno(&mut self, regno: u8) -> Result<()> {
        if regno as usize >= MAX_BPF_REG {
            verbose!(self, "R{} is invalid\n", regno);
            return Err(Errno::EINVAL);
        }
        Ok(())
    }

    fn do_insn(&mut self, pc: usize, st: &mut State) -> Result<Next> {
        let insn = self.insns[pc];
        let class = bpf_class(insn.code);
        // `check_alu_op` checks the reserved fields before the registers. The other classes
        // check the registers first here, because they use the register numbers at once.
        if !matches!(class, BPF_ALU | BPF_ALU64) {
            self.check_regno(insn.dst_reg)?;
            self.check_regno(insn.src_reg)?;
        }
        match class {
            BPF_ALU | BPF_ALU64 => {
                self.check_alu_op(insn, st)?;
                Ok(Next::Go(pc + 1))
            }
            BPF_LDX => {
                let src = self.read_reg(st, insn.src_reg)?;
                self.check_dst(insn.dst_reg)?;
                let size = bpf_size_to_bytes(bpf_size(insn.code));
                let v = self.check_mem_access(
                    st,
                    insn.src_reg,
                    src,
                    insn.off,
                    size,
                    Access::Read,
                    None,
                )?;
                self.save_aux_ptr_type(pc, src.ty)?;
                st.regs[insn.dst_reg as usize] =
                    if bpf_mode(insn.code) == BPF_MEMSX { Reg::unknown() } else { v };
                Ok(Next::Go(pc + 1))
            }
            BPF_STX if bpf_mode(insn.code) == BPF_ATOMIC => {
                self.check_atomic(insn, st)?;
                Ok(Next::Go(pc + 1))
            }
            BPF_STX => {
                let src = self.read_reg(st, insn.src_reg)?;
                let dst = self.read_reg(st, insn.dst_reg)?;
                if insn.imm != 0 {
                    verbose!(self, "BPF_STX uses reserved fields\n");
                    return Err(Errno::EINVAL);
                }
                let size = bpf_size_to_bytes(bpf_size(insn.code));
                self.check_mem_access(
                    st,
                    insn.dst_reg,
                    dst,
                    insn.off,
                    size,
                    Access::Write,
                    Some((insn.src_reg, src)),
                )?;
                self.save_aux_ptr_type(pc, dst.ty)?;
                Ok(Next::Go(pc + 1))
            }
            BPF_ST => {
                if insn.src_reg != 0 {
                    verbose!(self, "BPF_ST uses reserved fields\n");
                    return Err(Errno::EINVAL);
                }
                let dst = self.read_reg(st, insn.dst_reg)?;
                if dst.ty == RegType::PtrToCtx {
                    verbose!(self, "BPF_ST stores into R{} ctx is not allowed\n", insn.dst_reg);
                    return Err(Errno::EACCES);
                }
                let size = bpf_size_to_bytes(bpf_size(insn.code));
                let v = Reg::known(insn.imm as i64 as u64);
                self.check_mem_access(
                    st,
                    insn.dst_reg,
                    dst,
                    insn.off,
                    size,
                    Access::Write,
                    Some((u8::MAX, v)),
                )?;
                self.save_aux_ptr_type(pc, dst.ty)?;
                Ok(Next::Go(pc + 1))
            }
            BPF_LD if insn.is_ld_imm64() => {
                if insn.off != 0 {
                    verbose!(self, "BPF_LD_IMM64 uses reserved fields\n");
                    return Err(Errno::EINVAL);
                }
                self.check_dst(insn.dst_reg)?;
                let next = self.insns[pc + 1];
                st.regs[insn.dst_reg as usize] = match insn.src_reg {
                    0 => {
                        Reg::known(u64::from(insn.imm as u32) | (u64::from(next.imm as u32) << 32))
                    }
                    // `resolve_pseudo_ldimm64` checked the offset of the value.
                    BPF_PSEUDO_MAP_VALUE => Reg {
                        map: insn.imm as usize,
                        off: next.imm,
                        ..Reg::ptr(RegType::PtrToMapValue)
                    },
                    _ => Reg { map: insn.imm as usize, ..Reg::ptr(RegType::ConstPtrToMap) },
                };
                Ok(Next::Go(pc + 2))
            }
            BPF_LD if matches!(bpf_mode(insn.code), BPF_ABS | BPF_IND) => {
                self.check_ld_abs(insn, st)?;
                Ok(Next::Go(pc + 1))
            }
            BPF_LD => {
                verbose!(self, "invalid BPF_LD mode\n");
                Err(Errno::EINVAL)
            }
            _ => self.check_jmp(pc, insn, st),
        }
    }

    /// `check_alu_op` of Linux.
    fn check_alu_op(&mut self, insn: BpfInsn, st: &mut State) -> Result<()> {
        let alu64 = bpf_class(insn.code) == BPF_ALU64;
        let op = bpf_op(insn.code);
        let x = bpf_src(insn.code) == BPF_X;
        let d = insn.dst_reg;
        match op {
            BPF_END | BPF_NEG => {
                if insn.src_reg != 0
                    || insn.off != 0
                    || (op == BPF_NEG && insn.imm != 0)
                    || (op == BPF_END && !matches!(insn.imm, 16 | 32 | 64))
                    || (op == BPF_END && alu64 && x)
                {
                    let name = if op == BPF_NEG { "BPF_NEG" } else { "BPF_END" };
                    verbose!(self, "{} uses reserved fields\n", name);
                    return Err(Errno::EINVAL);
                }
                let dst = self.read_reg(st, d)?;
                self.check_dst(d)?;
                if dst.is_pointer() {
                    verbose!(self, "R{} pointer arithmetic prohibited\n", d);
                    return Err(Errno::EACCES);
                }
                st.regs[d as usize] = if dst.is_const() {
                    let v = dst.var.value;
                    let r = if op == BPF_NEG {
                        if alu64 { v.wrapping_neg() } else { u64::from((v as u32).wrapping_neg()) }
                    } else {
                        endian_const(alu64, x, insn.imm, v)
                    };
                    Reg::known(r)
                } else if op == BPF_END && insn.imm < 64 {
                    Reg::unknown_of_size(insn.imm as u32 / 8)
                } else if alu64 {
                    Reg::unknown()
                } else {
                    Reg::unknown_of_size(4)
                };
                Ok(())
            }
            BPF_MOV => {
                let bad = if x {
                    insn.imm != 0
                        || !(insn.off == 0
                            || (alu64 && matches!(insn.off, 8 | 16 | 32))
                            || (!alu64 && matches!(insn.off, 8 | 16)))
                } else {
                    insn.src_reg != 0 || insn.off != 0
                };
                if bad {
                    verbose!(self, "BPF_MOV uses reserved fields\n");
                    return Err(Errno::EINVAL);
                }
                self.check_dst(d)?;
                let r = if x {
                    let src = self.read_reg(st, insn.src_reg)?;
                    if insn.off != 0 {
                        if src.is_pointer() {
                            verbose!(self, "R{} sign-extension part of pointer\n", insn.src_reg);
                            return Err(Errno::EACCES);
                        }
                        if src.is_const() {
                            let v = src.var.value;
                            let sx = match insn.off {
                                8 => v as i8 as i64 as u64,
                                16 => v as i16 as i64 as u64,
                                _ => v as i32 as i64 as u64,
                            };
                            Reg::known(if alu64 { sx } else { sx as u32 as u64 })
                        } else if alu64 {
                            Reg::unknown()
                        } else {
                            Reg::unknown_of_size(4)
                        }
                    } else if alu64 {
                        src
                    } else if src.is_pointer() {
                        if !self.allow_ptr_leaks {
                            verbose!(self, "R{} partial copy of pointer\n", insn.src_reg);
                            return Err(Errno::EACCES);
                        }
                        Reg::unknown_of_size(4)
                    } else {
                        zext32(src)
                    }
                } else if alu64 {
                    Reg::known(insn.imm as i64 as u64)
                } else {
                    Reg::known(u64::from(insn.imm as u32))
                };
                st.regs[d as usize] = r;
                Ok(())
            }
            _ if op > BPF_END => {
                verbose!(self, "invalid BPF_ALU opcode {:x}\n", op);
                Err(Errno::EINVAL)
            }
            _ => {
                let off_ok = insn.off == 0 || (insn.off == 1 && matches!(op, BPF_DIV | BPF_MOD));
                let bad = if x { insn.imm != 0 || !off_ok } else { insn.src_reg != 0 || !off_ok };
                if bad {
                    verbose!(self, "BPF_ALU uses reserved fields\n");
                    return Err(Errno::EINVAL);
                }
                let dst = self.read_reg(st, d)?;
                let src = if x {
                    self.read_reg(st, insn.src_reg)?
                } else {
                    Reg::known(insn.imm as i64 as u64)
                };
                if !x && matches!(op, BPF_DIV | BPF_MOD) && insn.imm == 0 {
                    verbose!(self, "div by zero\n");
                    return Err(Errno::EINVAL);
                }
                if !x && matches!(op, BPF_LSH | BPF_RSH | BPF_ARSH) {
                    let size = if alu64 { 64 } else { 32 };
                    if insn.imm < 0 || insn.imm >= size {
                        verbose!(self, "invalid shift {}\n", insn.imm);
                        return Err(Errno::EINVAL);
                    }
                }
                self.check_dst(d)?;
                let r = self.adjust_reg_min_max_vals(insn, alu64, op, dst, src)?;
                st.regs[d as usize] = r;
                Ok(())
            }
        }
    }

    /// `adjust_reg_min_max_vals` of Linux.
    fn adjust_reg_min_max_vals(
        &mut self,
        insn: BpfInsn,
        alu64: bool,
        op: u8,
        dst: Reg,
        src: Reg,
    ) -> Result<Reg> {
        let d = insn.dst_reg;
        if dst.is_pointer() || src.is_pointer() {
            if dst.is_pointer() && src.is_pointer() {
                if op == BPF_SUB && alu64 && self.allow_ptr_leaks {
                    // The difference of two pointers is a scalar.
                    return Ok(Reg::unknown());
                }
                verbose!(
                    self,
                    "R{} pointer {}= pointer prohibited\n",
                    d,
                    if op == BPF_SUB { "-" } else { "op" }
                );
                return Err(Errno::EACCES);
            }
            if !alu64 {
                verbose!(self, "R{} 32-bit pointer arithmetic prohibited\n", d);
                return Err(Errno::EACCES);
            }
            if dst.is_pointer() {
                return self.adjust_ptr_min_max_vals(d, op, dst, src);
            }
            if op == BPF_ADD {
                return self.adjust_ptr_min_max_vals(d, op, src, dst);
            }
            verbose!(self, "R{} tried to subtract pointer from scalar\n", d);
            return Err(Errno::EACCES);
        }
        if alu64 {
            Ok(scalar_alu(op, insn.off, dst, src, 64))
        } else {
            Ok(scalar_alu(op, insn.off, zext32(dst), zext32(src), 32))
        }
    }

    /// Pointer plus or minus a scalar, `adjust_ptr_min_max_vals` of Linux.
    fn adjust_ptr_min_max_vals(&mut self, d: u8, op: u8, ptr: Reg, off: Reg) -> Result<Reg> {
        match ptr.ty {
            RegType::PtrToMapValueOrNull => {
                verbose!(
                    self,
                    "R{} pointer arithmetic on {} prohibited, null-check it first\n",
                    d,
                    reg_type_str(ptr.ty)
                );
                return Err(Errno::EACCES);
            }
            RegType::ConstPtrToMap => {
                verbose!(
                    self,
                    "R{} pointer arithmetic on {} prohibited\n",
                    d,
                    reg_type_str(ptr.ty)
                );
                return Err(Errno::EACCES);
            }
            _ => {}
        }
        if op != BPF_ADD && op != BPF_SUB {
            verbose!(
                self,
                "R{} pointer arithmetic with {} operator prohibited\n",
                d,
                alu_op_name(op)
            );
            return Err(Errno::EACCES);
        }
        if off.smin <= -BPF_MAX_VAR_OFF || off.smax >= BPF_MAX_VAR_OFF {
            if off.is_const() {
                verbose!(
                    self,
                    "value {} makes {} pointer be out of bounds\n",
                    off.smin,
                    reg_type_str(ptr.ty)
                );
            } else {
                verbose!(
                    self,
                    "math between {} pointer and register with unbounded min value is not allowed\n",
                    reg_type_str(ptr.ty)
                );
            }
            return Err(Errno::EACCES);
        }
        let mut r = ptr;
        if off.is_const() {
            let v = off.smin as i32;
            let new = if op == BPF_ADD { r.off as i64 + v as i64 } else { r.off as i64 - v as i64 };
            if new <= -BPF_MAX_VAR_OFF || new >= BPF_MAX_VAR_OFF {
                verbose!(self, "{} pointer offset {} is not allowed\n", reg_type_str(ptr.ty), new);
                return Err(Errno::EACCES);
            }
            r.off = new as i32;
            return Ok(r);
        }
        // A variable offset is allowed only on a map value, and only upward.
        if ptr.ty != RegType::PtrToMapValue || op != BPF_ADD || off.smin < 0 {
            verbose!(self, "R{} variable {} offset prohibited\n", d, reg_type_str(ptr.ty));
            return Err(Errno::EACCES);
        }
        let umin = ptr.umin + off.umin;
        let umax = ptr.umax + off.umax;
        if umax >= BPF_MAX_VAR_OFF as u64 {
            verbose!(self, "R{} pointer arithmetic of map value goes out of range\n", d);
            return Err(Errno::EACCES);
        }
        r.var = ptr.var.add(off.var);
        r.umin = umin;
        r.umax = umax;
        r.smin = umin as i64;
        r.smax = umax as i64;
        r.bounds_sync();
        Ok(r)
    }

    /// Checks an access of `size` bytes at `reg + off`, as `check_mem_access` of Linux. A
    /// read gives the value. A write stores `val`, with its register number for the log.
    #[allow(clippy::too_many_arguments)]
    fn check_mem_access(
        &mut self,
        st: &mut State,
        regno: u8,
        reg: Reg,
        off: i16,
        size: u32,
        t: Access,
        val: Option<(u8, Reg)>,
    ) -> Result<Reg> {
        self.check_ptr_alignment(reg, off, size)?;
        if let Some((vregno, v)) = val
            && v.is_pointer()
            && !self.allow_ptr_leaks
            && reg.ty != RegType::PtrToStack
        {
            let into = if reg.ty == RegType::PtrToCtx { "ctx" } else { "map" };
            verbose!(self, "R{} leaks addr into {}\n", vregno, into);
            return Err(Errno::EACCES);
        }
        match reg.ty {
            RegType::PtrToStack => {
                let off = self.check_stack_off(regno, reg, off, size)?;
                let frameno = reg.frameno;
                self.grow_stack(st.subprog_of(frameno), -off);
                let cur = st.curframe();
                let stack = st.stack_of(frameno);
                if t == Access::Write {
                    let v = val.map(|(_, v)| v).unwrap_or_else(Reg::unknown);
                    if !self.allow_ptr_leaks {
                        // `check_stack_write_fixed_off` of Linux: only a whole register spills
                        // a pointer, and a pointer on the stack cannot be changed in part.
                        if v.is_pointer() && size != 8 {
                            verbose!(self, "invalid size of register spill\n");
                            return Err(Errno::EACCES);
                        }
                        let slot = &stack[(MAX_BPF_STACK as i64 + off) as usize / 8];
                        if size != 8 && slot.is_spill() && slot.spilled.is_pointer() {
                            verbose!(self, "attempt to corrupt spilled pointer on stack\n");
                            return Err(Errno::EACCES);
                        }
                    }
                    if v.ty == RegType::PtrToStack && size == 8 && frameno != cur {
                        verbose!(
                            self,
                            "cannot spill pointers to stack into stack frame of the caller\n"
                        );
                        return Err(Errno::EINVAL);
                    }
                    stack_write(stack, off, size, v);
                    Ok(Reg::NOT_INIT)
                } else {
                    self.stack_read(stack, off, size)
                }
            }
            RegType::PtrToMapValue => {
                let map = self.maps[reg.map].clone();
                let flags = map.map_flags;
                if t == Access::Write && flags & BPF_F_RDONLY_PROG != 0 {
                    verbose!(
                        self,
                        "write into map forbidden, value_size={} off={} size={}\n",
                        map.value_size,
                        reg.off as i64 + off as i64,
                        size
                    );
                    return Err(Errno::EACCES);
                }
                if t == Access::Read && flags & BPF_F_WRONLY_PROG != 0 {
                    verbose!(
                        self,
                        "read from map forbidden, value_size={} off={} size={}\n",
                        map.value_size,
                        reg.off as i64 + off as i64,
                        size
                    );
                    return Err(Errno::EACCES);
                }
                self.check_map_access(regno, reg, off, size, map.value_size)?;
                Ok(Reg::unknown_of_size(size))
            }
            RegType::PtrToCtx => {
                if reg.off != 0 || !reg.var.is_const() || reg.var.value != 0 {
                    verbose!(
                        self,
                        "dereference of modified ctx ptr R{} off={} disallowed\n",
                        regno,
                        reg.off
                    );
                    return Err(Errno::EACCES);
                }
                let off = i32::from(off);
                if !self.is_valid_ctx_access(off, size, t) {
                    verbose!(self, "invalid bpf_context access off={} size={}\n", off, size);
                    return Err(Errno::EACCES);
                }
                Ok(Reg::unknown_of_size(size))
            }
            _ => {
                verbose!(self, "R{} invalid mem access '{}'\n", regno, reg_type_str(reg.ty));
                Err(Errno::EACCES)
            }
        }
    }

    /// Keeps the pointer type of a load or a store, `save_aux_ptr_type` of Linux. An
    /// instruction cannot access the context on one path and other memory on another path.
    fn save_aux_ptr_type(&mut self, pc: usize, ty: RegType) -> Result<()> {
        let prev = self.ptr_types[pc];
        if prev == RegType::NotInit {
            self.ptr_types[pc] = ty;
        } else if ty != prev && (ty == RegType::PtrToCtx || prev == RegType::PtrToCtx) {
            verbose!(self, "same insn cannot be used with different pointers\n");
            return Err(Errno::EINVAL);
        }
        Ok(())
    }

    /// Checks the alignment of an access, `check_ptr_alignment` of Linux. An access of the stack
    /// must always be aligned. An access of other memory must be aligned only with
    /// `BPF_F_STRICT_ALIGNMENT`, or for an atomic instruction.
    fn check_ptr_alignment(&mut self, reg: Reg, off: i16, size: u32) -> Result<()> {
        let (desc, strict) = match reg.ty {
            RegType::PtrToStack => ("stack ", true),
            RegType::PtrToCtx => ("context ", self.strict_alignment),
            RegType::PtrToMapValue => ("value ", self.strict_alignment),
            _ => ("", self.strict_alignment),
        };
        if !(strict || self.strict_once) || size == 1 {
            return Ok(());
        }
        let reg_off = reg.var.add(Tnum::constant((reg.off as i64 + off as i64) as u64));
        // `tnum_is_aligned`.
        if (reg_off.value | reg_off.mask) & (u64::from(size) - 1) != 0 {
            verbose!(
                self,
                "misaligned {}access off {}+{}+{} size {}\n",
                desc,
                TnumStr(reg.var),
                reg.off,
                off,
                size
            );
            return Err(Errno::EACCES);
        }
        Ok(())
    }

    /// Checks an access of the stack and gives the offset from the frame pointer, as
    /// `check_stack_access_within_bounds` and `check_ptr_alignment` of Linux.
    fn check_stack_off(&mut self, regno: u8, reg: Reg, off: i16, size: u32) -> Result<i64> {
        if !reg.var.is_const() || reg.var.value != 0 {
            verbose!(self, "R{} variable stack access prohibited\n", regno);
            return Err(Errno::EACCES);
        }
        let off = reg.off as i64 + off as i64;
        if off < -(MAX_BPF_STACK as i64) || off + size as i64 > 0 {
            verbose!(self, "invalid stack R{} off={} size={}\n", regno, off, size);
            return Err(Errno::EACCES);
        }
        Ok(off)
    }

    /// Reads the stack, as `check_stack_read_fixed_off` of Linux.
    fn stack_read(&mut self, stack: &[StackSlot], off: i64, size: u32) -> Result<Reg> {
        let start = (MAX_BPF_STACK as i64 + off) as usize;
        let slot = &stack[start / 8];
        if slot.is_spill() {
            if size == 8 {
                return Ok(slot.spilled);
            }
            if slot.spilled.ty != RegType::Scalar {
                verbose!(self, "invalid size of register fill\n");
                return Err(Errno::EACCES);
            }
            return Ok(Reg::unknown_of_size(size));
        }
        // A loader with `CAP_PERFMON` can read bytes that the program did not write,
        // `allow_uninit_stack` of Linux.
        for b in start..start + size as usize {
            if stack[b / 8].slot_type[b % 8] == STACK_INVALID && !self.allow_ptr_leaks {
                verbose!(self, "invalid read from stack off {}+{} size {}\n", off, b - start, size);
                return Err(Errno::EACCES);
            }
        }
        Ok(Reg::unknown_of_size(size))
    }

    /// Checks an access of a map value, as `check_map_access` of Linux.
    fn check_map_access(
        &mut self,
        regno: u8,
        reg: Reg,
        off: i16,
        size: u32,
        value_size: u32,
    ) -> Result<()> {
        // `check_mem_region_access` of Linux.
        let off = reg.off as i64 + off as i64;
        if reg.smin < 0
            && (reg.smin == i64::MIN
                || off + reg.smin != i64::from((off + reg.smin) as i32)
                || reg.smin + off < 0)
        {
            verbose!(
                self,
                "R{} min value is negative, either use unsigned index or do a if (index >=0) check.\n",
                regno
            );
            return Err(Errno::EACCES);
        }
        if !self.check_mem_size(reg.smin + off, size, value_size) {
            verbose!(self, "R{} min value is outside of the allowed memory range\n", regno);
            return Err(Errno::EACCES);
        }
        if reg.umax >= BPF_MAX_VAR_OFF as u64 {
            verbose!(
                self,
                "R{} unbounded memory access, make sure to bounds check any such access\n",
                regno
            );
            return Err(Errno::EACCES);
        }
        if !self.check_mem_size(reg.umax as i64 + off, size, value_size) {
            verbose!(self, "R{} max value is outside of the allowed memory range\n", regno);
            return Err(Errno::EACCES);
        }
        Ok(())
    }

    /// Tells if an access of a map value is in the value, and logs the error if not, as
    /// `__check_mem_access` of Linux.
    fn check_mem_size(&mut self, off: i64, size: u32, value_size: u32) -> bool {
        if off >= 0 && size > 0 && off as u64 + u64::from(size) <= u64::from(value_size) {
            return true;
        }
        verbose!(
            self,
            "invalid access to map value, value_size={} off={} size={}\n",
            value_size,
            off as i32,
            size
        );
        false
    }

    /// The `is_valid_access` of the program type, as `bpf_verifier_ops` of Linux.
    fn is_valid_ctx_access(&self, off: i32, size: u32, t: Access) -> bool {
        if off < 0 || !(off as u32).is_multiple_of(size) {
            return false;
        }
        let off = off as u32;
        match self.prog_type {
            BPF_PROG_TYPE_SOCKET_FILTER => {
                skb_is_valid_access(off, size, t, false, self.bpf_capable)
            }
            BPF_PROG_TYPE_CGROUP_SKB => skb_is_valid_access(off, size, t, true, self.bpf_capable),
            BPF_PROG_TYPE_CGROUP_SOCK => {
                sock_filter_is_valid_access(off, size, t, self.expected_attach_type)
            }
            BPF_PROG_TYPE_CGROUP_SOCK_ADDR => {
                sock_addr_is_valid_access(off, size, t, self.expected_attach_type)
            }
            BPF_PROG_TYPE_CGROUP_DEVICE => cgroup_dev_is_valid_access(off, size, t),
            _ => false,
        }
    }

    /// Checks the value of R0 at the exit, `check_return_code` of Linux. A program of a cgroup
    /// gives 0 or 1, and an egress program of `BPF_PROG_TYPE_CGROUP_SKB` can also give 2 or 3
    /// to tell about congestion.
    fn check_return_code(&mut self, r0: Reg) -> Result<()> {
        let (lo, hi) = match self.prog_type {
            BPF_PROG_TYPE_CGROUP_SKB if self.expected_attach_type == BPF_CGROUP_INET_EGRESS => {
                (0, 3)
            }
            // A program of `bind` can give 2 or 3 to bind a low port without
            // `CAP_NET_BIND_SERVICE`.
            BPF_PROG_TYPE_CGROUP_SOCK_ADDR
                if matches!(
                    self.expected_attach_type,
                    BPF_CGROUP_INET4_BIND | BPF_CGROUP_INET6_BIND
                ) =>
            {
                (0, 3)
            }
            BPF_PROG_TYPE_CGROUP_SOCK_ADDR
                if matches!(
                    self.expected_attach_type,
                    BPF_CGROUP_UDP4_RECVMSG
                        | BPF_CGROUP_UDP6_RECVMSG
                        | BPF_CGROUP_INET4_GETPEERNAME
                        | BPF_CGROUP_INET6_GETPEERNAME
                        | BPF_CGROUP_INET4_GETSOCKNAME
                        | BPF_CGROUP_INET6_GETSOCKNAME
                        | BPF_CGROUP_UNIX_RECVMSG
                        | BPF_CGROUP_UNIX_GETPEERNAME
                        | BPF_CGROUP_UNIX_GETSOCKNAME
                ) =>
            {
                (1, 1)
            }
            BPF_PROG_TYPE_CGROUP_SKB
            | BPF_PROG_TYPE_CGROUP_SOCK
            | BPF_PROG_TYPE_CGROUP_SOCK_ADDR
            | BPF_PROG_TYPE_CGROUP_DEVICE => (0, 1),
            _ => return Ok(()),
        };
        if r0.is_pointer() {
            verbose!(
                self,
                "At program exit the register R0 is not a known value ({})\n",
                reg_type_str(r0.ty)
            );
            return Err(Errno::EINVAL);
        }
        // The 32-bit value is the result, as `return_32bit` of Linux.
        let (min, max) = if r0.umax <= u64::from(u32::MAX) {
            (r0.umin as i64, r0.umax as i64)
        } else {
            (r0.smin, r0.smax)
        };
        if min < lo || max > hi {
            verbose!(
                self,
                "At program exit the register R0 has smin={} smax={} should have been in [{}, {}]\n",
                min,
                max,
                lo,
                hi
            );
            return Err(Errno::EINVAL);
        }
        // A value of 2 or 3 is only for egress, `enforce_attach_type_range` of Linux.
        if self.prog_type == BPF_PROG_TYPE_CGROUP_SKB && hi == 3 && max >= 2 {
            self.enforce_expected_attach_type = true;
        }
        Ok(())
    }

    /// `BPF_STX | BPF_ATOMIC`, `check_atomic` of Linux.
    fn check_atomic(&mut self, insn: BpfInsn, st: &mut State) -> Result<()> {
        let imm = insn.imm;
        let base = imm & !BPF_FETCH;
        let ok = matches!(base, 0x00 | 0x40 | 0x50 | 0xa0) || imm == BPF_XCHG || imm == BPF_CMPXCHG;
        if !ok {
            verbose!(self, "BPF_ATOMIC uses invalid atomic opcode {:02x}\n", imm);
            return Err(Errno::EINVAL);
        }
        let size = bpf_size_to_bytes(bpf_size(insn.code));
        let src = self.read_reg(st, insn.src_reg)?;
        let dst = self.read_reg(st, insn.dst_reg)?;
        if imm == BPF_CMPXCHG {
            let r0 = self.read_reg(st, 0)?;
            if r0.is_pointer() && !self.allow_ptr_leaks {
                verbose!(self, "R0 leaks addr into mem\n");
                return Err(Errno::EACCES);
            }
        }
        if src.is_pointer() && !self.allow_ptr_leaks {
            verbose!(self, "R{} leaks addr into mem\n", insn.src_reg);
            return Err(Errno::EACCES);
        }
        match dst.ty {
            RegType::PtrToCtx => {
                verbose!(
                    self,
                    "BPF_ATOMIC stores into R{} {} is not allowed\n",
                    insn.dst_reg,
                    reg_type_str(dst.ty)
                );
                return Err(Errno::EACCES);
            }
            _ => {}
        }
        let load_reg = if imm == BPF_CMPXCHG {
            Some(0)
        } else if imm & BPF_FETCH != 0 {
            self.check_dst(insn.src_reg)?;
            Some(insn.src_reg)
        } else {
            None
        };
        // The interpreter needs an aligned word for the atomic operation. A fetch gets the old
        // value, which can be a pointer that the program spilled to the stack.
        self.strict_once = true;
        let old = self.check_mem_access(st, insn.dst_reg, dst, insn.off, size, Access::Read, None);
        let r = old.and_then(|old| {
            self.check_mem_access(
                st,
                insn.dst_reg,
                dst,
                insn.off,
                size,
                Access::Write,
                Some((u8::MAX, Reg::unknown_of_size(size))),
            )?;
            Ok(old)
        });
        self.strict_once = false;
        if let Some(load_reg) = load_reg {
            st.regs[load_reg as usize] = r?;
        } else {
            r?;
        }
        Ok(())
    }

    /// The jump instructions, `check_cond_jmp_op`, `check_helper_call` and `check_return_code`
    /// of Linux.
    fn check_jmp(&mut self, pc: usize, insn: BpfInsn, st: &mut State) -> Result<Next> {
        let class = bpf_class(insn.code);
        let op = bpf_op(insn.code);
        match op {
            BPF_CALL => {
                if insn.off != 0
                    || insn.dst_reg != 0
                    || !matches!(insn.src_reg, 0 | BPF_PSEUDO_CALL)
                {
                    verbose!(self, "BPF_CALL uses reserved fields\n");
                    return Err(Errno::EINVAL);
                }
                if insn.src_reg == BPF_PSEUDO_CALL {
                    return self.check_func_call(pc, insn, st);
                }
                self.check_helper_call(insn.imm, st)?;
                Ok(Next::Go(pc + 1))
            }
            BPF_EXIT => {
                if insn.imm != 0 || insn.src_reg != 0 || insn.dst_reg != 0 || insn.off != 0 {
                    verbose!(self, "BPF_EXIT uses reserved fields\n");
                    return Err(Errno::EINVAL);
                }
                if !st.callers.is_empty() {
                    return self.prepare_func_exit(st);
                }
                let r0 = st.regs[0];
                if r0.ty == RegType::NotInit {
                    verbose!(self, "R0 !read_ok\n");
                    return Err(Errno::EACCES);
                }
                // A loader with `CAP_PERFMON` can return a pointer, `is_pointer_value` of Linux.
                if r0.is_pointer() && !self.allow_ptr_leaks {
                    verbose!(self, "R0 leaks addr as return value\n");
                    return Err(Errno::EACCES);
                }
                self.check_return_code(r0)?;
                Ok(Next::Exit)
            }
            BPF_JA => {
                let bad = if class == BPF_JMP {
                    insn.imm != 0 || insn.src_reg != 0 || insn.dst_reg != 0
                } else {
                    insn.off != 0 || insn.src_reg != 0 || insn.dst_reg != 0
                };
                if bad {
                    verbose!(self, "BPF_JA uses reserved fields\n");
                    return Err(Errno::EINVAL);
                }
                let off = if class == BPF_JMP32 { insn.imm as i64 } else { insn.off as i64 };
                Ok(Next::Go((pc as i64 + 1 + off) as usize))
            }
            _ => {
                if op > BPF_JSLE {
                    verbose!(self, "invalid BPF_JMP/JMP32 opcode {:x}\n", op);
                    return Err(Errno::EINVAL);
                }
                let x = bpf_src(insn.code) == BPF_X;
                if (x && insn.imm != 0) || (!x && insn.src_reg != 0) {
                    verbose!(self, "BPF_JMP/JMP32 uses reserved fields\n");
                    return Err(Errno::EINVAL);
                }
                let dst = self.read_reg(st, insn.dst_reg)?;
                let src = if x {
                    self.read_reg(st, insn.src_reg)?
                } else {
                    Reg::known(insn.imm as i64 as u64)
                };
                let target = (pc as i64 + 1 + insn.off as i64) as usize;
                self.check_cond_jmp_op(
                    pc,
                    target,
                    class == BPF_JMP32,
                    op,
                    insn.dst_reg,
                    dst,
                    src,
                    st,
                )
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn check_cond_jmp_op(
        &mut self,
        pc: usize,
        target: usize,
        jmp32: bool,
        op: u8,
        d: u8,
        dst: Reg,
        src: Reg,
        st: &mut State,
    ) -> Result<Next> {
        // The NULL check of a map value, `mark_ptr_or_null_regs` of Linux.
        if dst.ty == RegType::PtrToMapValueOrNull
            && !jmp32
            && matches!(op, BPF_JEQ | BPF_JNE)
            && src.is_const()
            && src.var.value == 0
        {
            let mut other = st.clone();
            let (null_state, ptr_state) =
                if op == BPF_JEQ { (&mut other, &mut *st) } else { (&mut *st, &mut other) };
            mark_ptr_or_null_regs(null_state, dst.id, true);
            mark_ptr_or_null_regs(ptr_state, dst.id, false);
            // `st` is the fall-through state and `other` the jump state.
            return Ok(Next::Branch(pc + 1, target, Box::new(other)));
        }
        if dst.is_pointer() || src.is_pointer() {
            if !self.allow_ptr_leaks {
                verbose!(self, "R{} pointer comparison prohibited\n", d);
                return Err(Errno::EACCES);
            }
            return Ok(Next::Branch(pc + 1, target, Box::new(st.clone())));
        }
        // A comparison of 32 bits with a constant is a comparison of 64 bits when the upper
        // half of `dst` follows from the lower half. Then the bounds of 64 bits refine as for
        // JMP. Otherwise the verifier learns nothing.
        let (a, b, both_const) = if !jmp32 {
            (dst, src, false)
        } else if dst.is_const() && src.is_const() {
            (zext32(dst), zext32(src), true)
        } else {
            match jmp32_as_jmp64(op, dst, src) {
                Some(b) => (dst, b, false),
                None => (Reg::unknown(), Reg::unknown(), false),
            }
        };
        match is_branch_taken(op, a, b, both_const) {
            Some(true) => Ok(Next::Go(target)),
            Some(false) => Ok(Next::Go(pc + 1)),
            None => {
                let mut other = st.clone();
                if a == dst && b.is_const() {
                    // `reg_set_min_max` of Linux, for a comparison with a constant.
                    let taken = refine(op, dst, b.var.value, true);
                    let not_taken = refine(op, dst, b.var.value, false);
                    match (taken, not_taken) {
                        (Some(t), Some(f)) => {
                            other.regs[d as usize] = t;
                            st.regs[d as usize] = f;
                        }
                        (Some(t), None) => {
                            st.regs[d as usize] = t;
                            return Ok(Next::Go(target));
                        }
                        (None, Some(f)) => {
                            st.regs[d as usize] = f;
                            return Ok(Next::Go(pc + 1));
                        }
                        (None, None) => return Ok(Next::Exit),
                    }
                }
                Ok(Next::Branch(pc + 1, target, Box::new(other)))
            }
        }
    }

    /// A call of a function of the program, `check_func_call` of Linux. Without BTF each
    /// function is static, so the verifier checks it again at each call, in a new frame.
    fn check_func_call(&mut self, pc: usize, insn: BpfInsn, st: &mut State) -> Result<Next> {
        let target = (pc as i64 + insn.imm as i64 + 1) as usize;
        let subprog = self.find_subprog(target).ok_or(Errno::EFAULT)?;
        // `setup_func_entry`.
        let cur = st.curframe() as usize;
        if cur + 1 >= MAX_CALL_FRAMES {
            verbose!(self, "the call stack of {} frames is too deep\n", cur + 2);
            return Err(Errno::E2BIG);
        }
        // The function gets R1 to R5 and a new frame pointer, as `set_callee_state`.
        let mut regs = Box::new([Reg::NOT_INIT; MAX_BPF_REG]);
        regs[1..=5].copy_from_slice(&st.regs[1..=5]);
        regs[BPF_REG_FP as usize] =
            Reg { frameno: cur as u32 + 1, ..Reg::ptr(RegType::PtrToStack) };
        // `clear_caller_saved_regs`.
        let mut caller_regs = core::mem::replace(&mut st.regs, regs);
        for r in caller_regs.iter_mut().take(6) {
            *r = Reg::NOT_INIT;
        }
        let stack = core::mem::replace(&mut st.stack, vec![StackSlot::EMPTY; SLOTS]);
        st.callers.push(Frame { regs: caller_regs, stack, subprog: st.subprog, callsite: pc });
        st.subprog = subprog;
        Ok(Next::Go(target))
    }

    /// The exit of a function of the program, `prepare_func_exit` of Linux.
    fn prepare_func_exit(&mut self, st: &mut State) -> Result<Next> {
        let r0 = st.regs[0];
        if r0.ty == RegType::PtrToStack {
            verbose!(self, "cannot return stack pointer to the caller\n");
            return Err(Errno::EINVAL);
        }
        let caller = st.callers.pop().ok_or(Errno::EFAULT)?;
        st.regs = caller.regs;
        st.regs[0] = r0;
        st.stack = caller.stack;
        st.subprog = caller.subprog;
        Ok(Next::Go(caller.callsite + 1))
    }

    /// `BPF_LD | BPF_ABS` and `BPF_LD | BPF_IND`, `check_ld_abs` of Linux. The load reads the
    /// packet of the context in R6, and the interpreter ends the program with 0 when the load
    /// is out of the packet.
    fn check_ld_abs(&mut self, insn: BpfInsn, st: &mut State) -> Result<()> {
        const CTX_REG: u8 = 6;
        let mode = bpf_mode(insn.code);
        // `may_access_skb`.
        if self.prog_type != BPF_PROG_TYPE_SOCKET_FILTER {
            verbose!(self, "BPF_LD_[ABS|IND] instructions not allowed for this program type\n");
            return Err(Errno::EINVAL);
        }
        if insn.dst_reg != 0
            || insn.off != 0
            || bpf_size(insn.code) == BPF_DW
            || (mode == BPF_ABS && insn.src_reg != 0)
        {
            verbose!(self, "BPF_LD_[ABS|IND] uses reserved fields\n");
            return Err(Errno::EINVAL);
        }
        let ctx = self.read_reg(st, CTX_REG)?;
        if ctx.ty != RegType::PtrToCtx {
            verbose!(self, "at the time of BPF_LD_ABS|IND R6 != pointer to skb\n");
            return Err(Errno::EINVAL);
        }
        if mode == BPF_IND {
            self.read_reg(st, insn.src_reg)?;
        }
        // `check_ptr_off_reg`.
        if ctx.off != 0 {
            verbose!(
                self,
                "dereference of modified ctx ptr R{} off={} disallowed\n",
                CTX_REG,
                ctx.off
            );
            return Err(Errno::EACCES);
        }
        if !ctx.var.is_const() || ctx.var.value != 0 {
            verbose!(
                self,
                "variable ctx access var_off=({:#x}; {:#x}) disallowed\n",
                ctx.var.value,
                ctx.var.mask
            );
            return Err(Errno::EACCES);
        }
        for r in st.regs.iter_mut().take(6) {
            *r = Reg::NOT_INIT;
        }
        st.regs[0] = Reg::unknown();
        Ok(())
    }

    /// `check_helper_call` of Linux.
    fn check_helper_call(&mut self, func_id: i32, st: &mut State) -> Result<()> {
        let Some(fn_) = get_func_proto(self.prog_type, func_id, self.bpf_capable) else {
            verbose!(self, "invalid func unknown#{}\n", func_id);
            return Err(Errno::EINVAL);
        };
        let mut map: Option<usize> = None;
        for i in 0..5 {
            self.check_func_arg(st, &fn_, i, &mut map)?;
        }
        for r in 1..=5 {
            st.regs[r] = Reg::NOT_INIT;
        }
        st.regs[0] = match fn_.ret_type {
            RetType::Integer => Reg::unknown(),
            RetType::PtrToMapValueOrNull => {
                self.id_gen += 1;
                Reg {
                    map: map.unwrap_or(0),
                    id: self.id_gen,
                    ..Reg::ptr(RegType::PtrToMapValueOrNull)
                }
            }
            RetType::Void => Reg::NOT_INIT,
        };
        self.check_map_func_compatibility(map, func_id, &fn_)
    }

    /// Checks that the helper `func_id` can use the map of its arguments, as
    /// `check_map_func_compatibility` of Linux. Only `bpf_tail_call` can use a program array, and
    /// `bpf_tail_call` needs a program array.
    fn check_map_func_compatibility(
        &mut self,
        map: Option<usize>,
        func_id: i32,
        fn_: &BpfFuncProto,
    ) -> Result<()> {
        let Some(m) = map else {
            return Ok(());
        };
        let map_type = self.maps[m].map_type;
        let is_prog_array = map_type == BPF_MAP_TYPE_PROG_ARRAY;
        if is_prog_array != (func_id == BPF_FUNC_tail_call) {
            verbose!(
                self,
                "cannot pass map_type {} into func bpf_{}#{}\n",
                map_type,
                fn_.name,
                func_id
            );
            return Err(Errno::EINVAL);
        }
        // rukernel has no JIT, so a program with functions cannot use tail calls, as
        // `allow_tail_call_in_subprogs` of Linux without a JIT.
        if func_id == BPF_FUNC_tail_call && self.subprogs.len() > 1 {
            verbose!(self, "mixing of tail_calls and bpf-to-bpf calls is not supported\n");
            return Err(Errno::EINVAL);
        }
        Ok(())
    }

    /// `check_func_arg` of Linux.
    fn check_func_arg(
        &mut self,
        st: &mut State,
        fn_: &BpfFuncProto,
        arg: usize,
        map: &mut Option<usize>,
    ) -> Result<()> {
        let regno = arg as u8 + 1;
        let t = fn_.arg_type[arg];
        if t == ArgType::DontCare {
            return Ok(());
        }
        let reg = self.read_reg(st, regno)?;
        let expected = |env: &mut Self, want: &str| -> Result<()> {
            verbose!(env, "R{} type={} expected={}\n", regno, reg_type_str(reg.ty), want);
            Err(Errno::EACCES)
        };
        match t {
            ArgType::DontCare => {}
            ArgType::Anything => {
                if reg.is_pointer() && !self.allow_ptr_leaks {
                    verbose!(self, "R{} leaks addr into helper function\n", regno);
                    return Err(Errno::EACCES);
                }
            }
            ArgType::ConstMapPtr => {
                if reg.ty != RegType::ConstPtrToMap {
                    return expected(self, "map_ptr");
                }
                *map = Some(reg.map);
            }
            ArgType::PtrToCtx => {
                if reg.ty != RegType::PtrToCtx {
                    return expected(self, "ctx");
                }
                if reg.off != 0 {
                    verbose!(
                        self,
                        "dereference of modified ctx ptr R{} off={} disallowed\n",
                        regno,
                        reg.off
                    );
                    return Err(Errno::EACCES);
                }
            }
            ArgType::PtrToMapKey | ArgType::PtrToMapValue => {
                let Some(m) = *map else {
                    verbose!(self, "invalid map_ptr to access map->key\n");
                    return Err(Errno::EACCES);
                };
                let size = if t == ArgType::PtrToMapKey {
                    self.maps[m].key_size
                } else {
                    self.maps[m].value_size
                };
                self.check_helper_mem_access(st, regno, reg, size, Access::Read)?;
            }
            ArgType::PtrToUninitMem => {
                // The size is the next argument, `ARG_CONST_SIZE`.
                let size_reg = self.read_reg(st, regno + 1)?;
                if size_reg.is_pointer() {
                    verbose!(
                        self,
                        "R{} type={} expected=scalar\n",
                        regno + 1,
                        reg_type_str(size_reg.ty)
                    );
                    return Err(Errno::EACCES);
                }
                if size_reg.umin == 0 {
                    verbose!(
                        self,
                        "R{} invalid zero-sized read: u64=[{},{}]\n",
                        regno + 1,
                        size_reg.umin,
                        size_reg.umax
                    );
                    return Err(Errno::EACCES);
                }
                if size_reg.umax > MAX_BPF_STACK as u64 {
                    verbose!(
                        self,
                        "R{} unbounded memory access, use 'var &= const' or 'if (var < const)'\n",
                        regno + 1
                    );
                    return Err(Errno::EACCES);
                }
                self.check_helper_mem_access(st, regno, reg, size_reg.umax as u32, Access::Write)?;
            }
            ArgType::ConstSize => {}
        }
        Ok(())
    }

    /// Checks the memory that a helper reads or writes, as `check_helper_mem_access` and
    /// `check_stack_range_initialized` of Linux.
    fn check_helper_mem_access(
        &mut self,
        st: &mut State,
        regno: u8,
        reg: Reg,
        size: u32,
        t: Access,
    ) -> Result<()> {
        match reg.ty {
            RegType::PtrToStack => {
                if !reg.var.is_const() || reg.var.value != 0 {
                    verbose!(self, "R{} variable stack access prohibited\n", regno);
                    return Err(Errno::EACCES);
                }
                let off = reg.off as i64;
                if off < -(MAX_BPF_STACK as i64) || off + size as i64 > 0 || size == 0 {
                    verbose!(
                        self,
                        "invalid indirect access to stack R{} off={} size={}\n",
                        regno,
                        off,
                        size
                    );
                    return Err(Errno::EACCES);
                }
                self.grow_stack(st.subprog_of(reg.frameno), -off);
                let start = (MAX_BPF_STACK as i64 + off) as usize;
                let stack = st.stack_of(reg.frameno);
                for b in start..start + size as usize {
                    let slot = &mut stack[b / 8];
                    if t == Access::Write {
                        if slot.is_spill() {
                            slot.slot_type = [STACK_MISC; 8];
                            slot.spilled = Reg::NOT_INIT;
                        }
                        slot.slot_type[b % 8] = STACK_MISC;
                        continue;
                    }
                    let ok = match slot.slot_type[b % 8] {
                        STACK_MISC => true,
                        STACK_SPILL => slot.spilled.ty == RegType::Scalar || self.allow_ptr_leaks,
                        // `allow_uninit_stack` of Linux.
                        _ => self.allow_ptr_leaks,
                    };
                    if !ok {
                        verbose!(
                            self,
                            "invalid indirect read from stack R{} off {}+{} size {}\n",
                            regno,
                            off,
                            b - start,
                            size
                        );
                        return Err(Errno::EACCES);
                    }
                }
                Ok(())
            }
            RegType::PtrToMapValue => {
                let map = self.maps[reg.map].clone();
                if t == Access::Write && map.map_flags & BPF_F_RDONLY_PROG != 0 {
                    verbose!(
                        self,
                        "write into map forbidden, value_size={} off={} size={}\n",
                        map.value_size,
                        reg.off,
                        size
                    );
                    return Err(Errno::EACCES);
                }
                if t == Access::Read && map.map_flags & BPF_F_WRONLY_PROG != 0 {
                    verbose!(
                        self,
                        "read from map forbidden, value_size={} off={} size={}\n",
                        map.value_size,
                        reg.off,
                        size
                    );
                    return Err(Errno::EACCES);
                }
                self.check_map_access(regno, reg, 0, size, map.value_size)
            }
            _ => {
                verbose!(self, "R{} type={} expected=fp, map_value\n", regno, reg_type_str(reg.ty));
                Err(Errno::EACCES)
            }
        }
    }
}

/// What comes after an instruction.
enum Next {
    /// The next instruction.
    Go(usize),
    /// Both ways of a jump: the first one now, the second one with its state later.
    Branch(usize, usize, Box<State>),
    /// The end of the path.
    Exit,
}

/// The name of an ALU operation in the log.
fn alu_op_name(op: u8) -> &'static str {
    match op {
        BPF_ADD => "+=",
        BPF_SUB => "-=",
        BPF_MUL => "*=",
        BPF_DIV => "/=",
        BPF_OR => "|=",
        BPF_AND => "&=",
        BPF_LSH => "<<=",
        BPF_RSH => ">>=",
        BPF_MOD => "%=",
        BPF_XOR => "^=",
        BPF_ARSH => "s>>=",
        _ => "?",
    }
}

/// `BPF_END` on a known value.
fn endian_const(alu64: bool, x: bool, imm: i32, v: u64) -> u64 {
    let swap =
        alu64 || (x && cfg!(target_endian = "little")) || (!x && cfg!(target_endian = "big"));
    match (imm, swap) {
        (16, false) => v as u16 as u64,
        (16, true) => (v as u16).swap_bytes() as u64,
        (32, false) => v as u32 as u64,
        (32, true) => (v as u32).swap_bytes() as u64,
        (_, false) => v,
        (_, true) => v.swap_bytes(),
    }
}

/// The low 32 bits of a scalar, zero-extended.
fn zext32(r: Reg) -> Reg {
    if r.is_const() {
        return Reg::known(r.var.value as u32 as u64);
    }
    if r.umax <= u64::from(u32::MAX) {
        return r;
    }
    Reg::from_tnum(r.var.subreg())
}

/// An ALU operation on scalars, `adjust_scalar_min_max_vals` of Linux. For 32 bits, `dst` and
/// `src` are zero-extended and the result is cut to 32 bits.
fn scalar_alu(op: u8, off: i16, dst: Reg, src: Reg, bits: u32) -> Reg {
    let cut = |r: Reg| -> Reg {
        if bits == 64 {
            r
        } else if r.is_const() {
            Reg::known(r.var.value as u32 as u64)
        } else if r.umax <= u64::from(u32::MAX) {
            r
        } else {
            Reg::from_tnum(r.var.subreg())
        }
    };
    if dst.is_const() && src.is_const() {
        let (a, b) = (dst.var.value, src.var.value);
        let v = if bits == 64 {
            alu64_const(op, off, a, b)
        } else {
            u64::from(alu32_const(op, off, a as u32, b as u32))
        };
        return Reg::known(v);
    }
    let shift_ok = |s: &Reg| s.is_const() && s.var.value < u64::from(bits);
    let mut r = match op {
        BPF_ADD => {
            let mut r = Reg { var: dst.var.add(src.var), ..Reg::unknown() };
            if let (Some(lo), Some(hi)) =
                (dst.umin.checked_add(src.umin), dst.umax.checked_add(src.umax))
            {
                r.umin = lo;
                r.umax = hi;
            }
            if let (Some(lo), Some(hi)) =
                (dst.smin.checked_add(src.smin), dst.smax.checked_add(src.smax))
            {
                r.smin = lo;
                r.smax = hi;
            }
            r
        }
        BPF_SUB => {
            let mut r = Reg { var: dst.var.sub(src.var), ..Reg::unknown() };
            if dst.umin >= src.umax {
                r.umin = dst.umin - src.umax;
                r.umax = dst.umax - src.umin;
            }
            if let (Some(lo), Some(hi)) =
                (dst.smin.checked_sub(src.smax), dst.smax.checked_sub(src.smin))
            {
                r.smin = lo;
                r.smax = hi;
            }
            r
        }
        BPF_MUL => {
            let mut r = Reg { var: dst.var.mul(src.var), ..Reg::unknown() };
            if let Some(hi) = dst.umax.checked_mul(src.umax) {
                r.umin = dst.umin.wrapping_mul(src.umin);
                r.umax = hi;
            }
            r
        }
        BPF_AND => {
            let var = dst.var.and(src.var);
            Reg { var, umin: var.min(), umax: dst.umax.min(src.umax), ..Reg::unknown() }
        }
        BPF_OR => {
            let var = dst.var.or(src.var);
            Reg { var, umin: dst.umin.max(src.umin), umax: var.max(), ..Reg::unknown() }
        }
        BPF_XOR => Reg::from_tnum(dst.var.xor(src.var)),
        BPF_LSH if shift_ok(&src) => {
            let s = src.var.value as u32;
            let var = if bits == 32 { dst.var.lshift(s).subreg() } else { dst.var.lshift(s) };
            let mut r = Reg { var, ..Reg::unknown() };
            if bits == 64 && dst.umax.leading_zeros() >= s {
                r.umin = dst.umin << s;
                r.umax = dst.umax << s;
            }
            r
        }
        BPF_RSH if shift_ok(&src) => {
            let s = src.var.value as u32;
            Reg {
                var: dst.var.rshift(s),
                umin: dst.umin >> s,
                umax: dst.umax >> s,
                ..Reg::unknown()
            }
        }
        BPF_ARSH if shift_ok(&src) && bits == 64 => {
            let s = src.var.value as u32;
            Reg {
                var: dst.var.arshift(s, 64),
                smin: dst.smin >> s,
                smax: dst.smax >> s,
                ..Reg::unknown()
            }
        }
        BPF_DIV if off == 0 && src.is_const() && src.var.value != 0 => {
            let v = src.var.value;
            Reg { umin: dst.umin / v, umax: dst.umax / v, ..Reg::unknown() }
        }
        BPF_MOD if off == 0 && src.is_const() && src.var.value != 0 => {
            Reg { umax: dst.umax.min(src.var.value - 1), ..Reg::unknown() }
        }
        _ => Reg::unknown(),
    };
    if !r.bounds_sync() {
        r = Reg::unknown();
    }
    if bits == 32 {
        r = cut(r).with_unknown_signed();
    }
    r
}

/// An ALU64 operation on known values, as the interpreter does it.
fn alu64_const(op: u8, off: i16, a: u64, b: u64) -> u64 {
    match op {
        BPF_ADD => a.wrapping_add(b),
        BPF_SUB => a.wrapping_sub(b),
        BPF_MUL => a.wrapping_mul(b),
        BPF_DIV if b == 0 => 0,
        BPF_DIV if off == 1 => (a as i64).wrapping_div(b as i64) as u64,
        BPF_DIV => a / b,
        BPF_MOD if b == 0 => a,
        BPF_MOD if off == 1 => (a as i64).wrapping_rem(b as i64) as u64,
        BPF_MOD => a % b,
        BPF_OR => a | b,
        BPF_AND => a & b,
        BPF_XOR => a ^ b,
        BPF_LSH => a << (b & 63),
        BPF_RSH => a >> (b & 63),
        BPF_ARSH => ((a as i64) >> (b & 63)) as u64,
        _ => 0,
    }
}

/// An ALU32 operation on known values, as the interpreter does it.
fn alu32_const(op: u8, off: i16, a: u32, b: u32) -> u32 {
    match op {
        BPF_ADD => a.wrapping_add(b),
        BPF_SUB => a.wrapping_sub(b),
        BPF_MUL => a.wrapping_mul(b),
        BPF_DIV if b == 0 => 0,
        BPF_DIV if off == 1 => (a as i32).wrapping_div(b as i32) as u32,
        BPF_DIV => a / b,
        BPF_MOD if b == 0 => a,
        BPF_MOD if off == 1 => (a as i32).wrapping_rem(b as i32) as u32,
        BPF_MOD => a % b,
        BPF_OR => a | b,
        BPF_AND => a & b,
        BPF_XOR => a ^ b,
        BPF_LSH => a << (b & 31),
        BPF_RSH => a >> (b & 31),
        BPF_ARSH => ((a as i32) >> (b & 31)) as u32,
        _ => 0,
    }
}

/// Tells if a jump is always taken or never taken, as `is_branch_taken` of Linux. `None` is
/// both.
fn is_branch_taken(op: u8, a: Reg, b: Reg, jmp32: bool) -> Option<bool> {
    if a.is_const() && b.is_const() {
        let (x, y) = (a.var.value, b.var.value);
        let (sx, sy) =
            if jmp32 { (x as i32 as i64, y as i32 as i64) } else { (x as i64, y as i64) };
        return Some(match op {
            BPF_JEQ => x == y,
            BPF_JNE => x != y,
            BPF_JGT => x > y,
            BPF_JGE => x >= y,
            BPF_JLT => x < y,
            BPF_JLE => x <= y,
            BPF_JSET => x & y != 0,
            BPF_JSGT => sx > sy,
            BPF_JSGE => sx >= sy,
            BPF_JSLT => sx < sy,
            BPF_JSLE => sx <= sy,
            _ => return None,
        });
    }
    if jmp32 {
        return None;
    }
    match op {
        BPF_JEQ | BPF_JNE => {
            if !a.var.can_equal(b.var) || a.umin > b.umax || a.umax < b.umin {
                Some(op == BPF_JNE)
            } else {
                None
            }
        }
        BPF_JGT if a.umin > b.umax => Some(true),
        BPF_JGT if a.umax <= b.umin => Some(false),
        BPF_JGE if a.umin >= b.umax => Some(true),
        BPF_JGE if a.umax < b.umin => Some(false),
        BPF_JLT if a.umax < b.umin => Some(true),
        BPF_JLT if a.umin >= b.umax => Some(false),
        BPF_JLE if a.umax <= b.umin => Some(true),
        BPF_JLE if a.umin > b.umax => Some(false),
        BPF_JSGT if a.smin > b.smax => Some(true),
        BPF_JSGT if a.smax <= b.smin => Some(false),
        BPF_JSGE if a.smin >= b.smax => Some(true),
        BPF_JSGE if a.smax < b.smin => Some(false),
        BPF_JSLT if a.smax < b.smin => Some(true),
        BPF_JSLT if a.smin >= b.smax => Some(false),
        BPF_JSLE if a.smax <= b.smin => Some(true),
        BPF_JSLE if a.smin > b.smax => Some(false),
        BPF_JSET if b.is_const() && a.var.value & b.var.value != 0 => Some(true),
        BPF_JSET if b.is_const() && a.var.max() & b.var.value == 0 => Some(false),
        _ => None,
    }
}

/// The constant of 64 bits that `dst op src` of JMP compares with, when it gives the same result
/// as `dst op src` of JMP32. `src` must be a constant. When `dst` is a zero extension of its lower
/// 32 bits, the unsigned comparisons are the same with the zero extension of `src`. When `dst` is
/// a sign extension of its lower 32 bits, the signed comparisons are the same with the sign
/// extension of `src`. `BPF_JSET` is always the same with the zero extension.
fn jmp32_as_jmp64(op: u8, dst: Reg, src: Reg) -> Option<Reg> {
    if !src.is_const() || dst.ty != RegType::Scalar {
        return None;
    }
    let lo = src.var.value as u32;
    let zext = dst.umax <= u32::MAX as u64;
    let sext = dst.smin >= i32::MIN as i64 && dst.smax <= i32::MAX as i64;
    let v = match op {
        BPF_JSET => lo as u64,
        BPF_JGT | BPF_JGE | BPF_JLT | BPF_JLE if zext => lo as u64,
        BPF_JSGT | BPF_JSGE | BPF_JSLT | BPF_JSLE if sext => lo as i32 as i64 as u64,
        BPF_JEQ | BPF_JNE if zext => lo as u64,
        BPF_JEQ | BPF_JNE if sext => lo as i32 as i64 as u64,
        _ => return None,
    };
    Some(Reg::known(v))
}

/// The bounds of `r` when `r op v` is `taken`, as `reg_set_min_max` of Linux. `None` is a
/// path that cannot occur.
fn refine(op: u8, r: Reg, v: u64, taken: bool) -> Option<Reg> {
    let mut r = r;
    let sv = v as i64;
    if op == BPF_JSET {
        // When the jump is taken, a bit of `v` is set, and the verifier knows which bit only
        // when `v` has one bit. When it is not taken, all the bits of `v` are clear.
        if taken {
            if !v.is_power_of_two() {
                return Some(r);
            }
            r.var = r.var.or(Tnum::constant(v));
        } else {
            r.var = r.var.and(Tnum::constant(!v));
        }
        return if r.bounds_sync() { Some(r) } else { None };
    }
    // A jump that is not taken is the opposite comparison.
    let op = if taken {
        op
    } else {
        match op {
            BPF_JEQ => BPF_JNE,
            BPF_JNE => BPF_JEQ,
            BPF_JGT => BPF_JLE,
            BPF_JLE => BPF_JGT,
            BPF_JGE => BPF_JLT,
            BPF_JLT => BPF_JGE,
            BPF_JSGT => BPF_JSLE,
            BPF_JSLE => BPF_JSGT,
            BPF_JSGE => BPF_JSLT,
            BPF_JSLT => BPF_JSGE,
            _ => return Some(r),
        }
    };
    match op {
        BPF_JEQ => {
            if !r.var.can_equal(Tnum::constant(v)) {
                return None;
            }
            return Some(Reg { id: r.id, ..Reg::known(v) });
        }
        BPF_JNE => {
            if r.is_const() && r.var.value == v {
                return None;
            }
        }
        BPF_JGT => r.umin = r.umin.max(v.checked_add(1)?),
        BPF_JGE => r.umin = r.umin.max(v),
        BPF_JLT => r.umax = r.umax.min(v.checked_sub(1)?),
        BPF_JLE => r.umax = r.umax.min(v),
        BPF_JSGT => r.smin = r.smin.max(sv.checked_add(1)?),
        BPF_JSGE => r.smin = r.smin.max(sv),
        BPF_JSLT => r.smax = r.smax.min(sv.checked_sub(1)?),
        BPF_JSLE => r.smax = r.smax.min(sv),
        _ => {}
    }
    if r.bounds_sync() { Some(r) } else { None }
}

/// Marks the registers with the ID `id` as NULL or as a map value, as `mark_ptr_or_null_regs`
/// of Linux.
fn mark_ptr_or_null_regs(st: &mut State, id: u32, is_null: bool) {
    let mark = |r: &mut Reg| {
        if r.ty == RegType::PtrToMapValueOrNull && r.id == id {
            *r = if is_null {
                Reg::known(0)
            } else {
                Reg { ty: RegType::PtrToMapValue, id: 0, ..*r }
            };
        }
    };
    let frames = st.callers.iter_mut().map(|f| (&mut f.regs, &mut f.stack));
    for (regs, stack) in frames.chain(core::iter::once((&mut st.regs, &mut st.stack))) {
        regs.iter_mut().for_each(mark);
        for slot in stack.iter_mut() {
            if slot.is_spill() {
                mark(&mut slot.spilled);
            }
        }
    }
}

/// Writes the stack, as `check_stack_write_fixed_off` of Linux. A write of 8 bytes spills the
/// register. A smaller write makes the bytes `STACK_MISC`.
fn stack_write(stack: &mut [StackSlot], off: i64, size: u32, v: Reg) {
    let start = (MAX_BPF_STACK as i64 + off) as usize;
    let slot = &mut stack[start / 8];
    if size == 8 {
        slot.slot_type = [STACK_SPILL; 8];
        slot.spilled = v;
        return;
    }
    if slot.is_spill() {
        slot.slot_type = [STACK_MISC; 8];
        slot.spilled = Reg::NOT_INIT;
    }
    for b in start..start + size as usize {
        slot.slot_type[b % 8] = STACK_MISC;
    }
}

/// `sk_filter_is_valid_access` and `cg_skb_is_valid_access` of Linux, with
/// `bpf_skb_is_valid_access`. rukernel has no packet pointers and no `PTR_TO_SOCK_COMMON`, so a
/// program cannot read `data`, `data_end` or `sk`.
fn skb_is_valid_access(off: u32, size: u32, t: Access, cgroup: bool, bpf_capable: bool) -> bool {
    use sk_buff::*;
    let within = |start: u32, len: u32| (start..start + len).contains(&off);
    if cgroup {
        if within(TC_CLASSID, 4) || within(DATA_META, 4) || within(WIRE_LEN, 4) {
            return false;
        }
        if t == Access::Write
            && !(within(MARK, 4)
                || within(PRIORITY, 4)
                || (CB..CB_END).contains(&off)
                || (within(TSTAMP, 8) && bpf_capable))
        {
            return false;
        }
    } else {
        if within(TC_CLASSID, 4)
            || within(DATA, 4)
            || within(DATA_META, 4)
            || within(DATA_END, 4)
            || (FAMILY..LOCAL_PORT + 4).contains(&off)
            || within(TSTAMP, 8)
            || within(WIRE_LEN, 4)
            || within(HWTSTAMP, 8)
        {
            return false;
        }
        if t == Access::Write && !(CB..CB_END).contains(&off) {
            return false;
        }
    }
    // `bpf_skb_is_valid_access`.
    if off >= SIZE || !off.is_multiple_of(size) {
        return false;
    }
    if (CB..CB_END).contains(&off) {
        return off + size <= CB_END;
    }
    if within(DATA, 4) || within(DATA_META, 4) || within(DATA_END, 4) || within(SK, 8) {
        return false;
    }
    if (REMOTE_IP4..REMOTE_PORT).contains(&off) {
        return size == 4;
    }
    if within(FLOW_KEYS, 8) || off == TSTAMP_TYPE || (TSTAMP_TYPE + 1..HWTSTAMP).contains(&off) {
        return false;
    }
    if within(HWTSTAMP, 8) {
        return t == Access::Read && size == 8;
    }
    if within(TSTAMP, 8) {
        return size == 8;
    }
    if t == Access::Write {
        return size == 4;
    }
    // `bpf_ctx_narrow_access_ok`.
    size <= 4
}

/// `sock_filter_is_valid_access` of Linux: `bpf_sock_is_valid_access` and
/// `__sock_filter_check_attach_type`.
fn sock_filter_is_valid_access(off: u32, size: u32, t: Access, attach_type: u32) -> bool {
    use crate::prog::bpf_sock::*;
    if off >= SIZE {
        return false;
    }
    let field = off & !3;
    // `bpf_sock_is_valid_access`.
    let size_ok = match field {
        STATE | FAMILY | TYPE | PROTOCOL | SRC_PORT | RX_QUEUE_MAPPING | SRC_IP4 | DST_IP4 => {
            size <= 4
        }
        _ if (SRC_IP6..SRC_IP6 + 16).contains(&field)
            || (DST_IP6..DST_IP6 + 16).contains(&field) =>
        {
            size <= 4
        }
        // `dst_port` is a 16-bit field, and a 32-bit read of it is also allowed.
        DST_PORT => size == 4 || off + size <= DST_PORT + 2,
        _ => size == 4 && off == field,
    };
    if !size_ok {
        return false;
    }
    // `__sock_filter_check_attach_type`.
    let full = |types: &[u32]| types.contains(&attach_type);
    match field {
        BOUND_DEV_IF | MARK | PRIORITY => {
            full(&[BPF_CGROUP_INET_SOCK_CREATE, BPF_CGROUP_INET_SOCK_RELEASE])
        }
        SRC_IP4 => full(&[BPF_CGROUP_INET4_POST_BIND]) && t == Access::Read,
        _ if (SRC_IP6..SRC_IP6 + 16).contains(&field) => {
            full(&[BPF_CGROUP_INET6_POST_BIND]) && t == Access::Read
        }
        SRC_PORT => {
            full(&[BPF_CGROUP_INET4_POST_BIND, BPF_CGROUP_INET6_POST_BIND]) && t == Access::Read
        }
        _ => t == Access::Read,
    }
}

/// `sock_addr_is_valid_access` of Linux. A field of an address is only for the attach types
/// of its family. rukernel has no `PTR_TO_SOCKET`, so the field `sk` cannot be read.
fn sock_addr_is_valid_access(off: u32, size: u32, t: Access, attach_type: u32) -> bool {
    use crate::prog::bpf_sock_addr::*;
    if off >= SIZE {
        return false;
    }
    let field = off & !3;
    let is = |types: &[u32]| types.contains(&attach_type);
    let family_ok = match field {
        USER_IP4 => is(&[
            BPF_CGROUP_INET4_BIND,
            BPF_CGROUP_INET4_CONNECT,
            BPF_CGROUP_INET4_GETPEERNAME,
            BPF_CGROUP_INET4_GETSOCKNAME,
            BPF_CGROUP_UDP4_SENDMSG,
            BPF_CGROUP_UDP4_RECVMSG,
        ]),
        f if (USER_IP6..USER_PORT).contains(&f) => is(&[
            BPF_CGROUP_INET6_BIND,
            BPF_CGROUP_INET6_CONNECT,
            BPF_CGROUP_INET6_GETPEERNAME,
            BPF_CGROUP_INET6_GETSOCKNAME,
            BPF_CGROUP_UDP6_SENDMSG,
            BPF_CGROUP_UDP6_RECVMSG,
        ]),
        MSG_SRC_IP4 => is(&[BPF_CGROUP_UDP4_SENDMSG]),
        f if (MSG_SRC_IP6..SK).contains(&f) => is(&[BPF_CGROUP_UDP6_SENDMSG]),
        _ => true,
    };
    if !family_ok {
        return false;
    }
    // An 8-byte access of an IPv6 address, `bpf_ctx_wide_access_ok` of Linux. The access must be
    // aligned and in the address. The address `msg_src_ip6` ends at 60.
    let in_field = |start: u32, end: u32| start <= off && off + size <= end;
    let wide = size == 8
        && off.is_multiple_of(8)
        && (in_field(USER_IP6, USER_PORT) || in_field(MSG_SRC_IP6, MSG_SRC_IP6 + 16));
    match field {
        USER_IP4 | USER_PORT | MSG_SRC_IP4 => {
            if t == Access::Read {
                size <= 4
            } else {
                size == 4
            }
        }
        f if (USER_IP6..USER_PORT).contains(&f) || (MSG_SRC_IP6..SK).contains(&f) => {
            wide || if t == Access::Read { size <= 4 } else { size == 4 }
        }
        USER_FAMILY | FAMILY | TYPE | PROTOCOL => t == Access::Read && size == 4,
        _ => false,
    }
}

/// `cgroup_dev_is_valid_access` of Linux: the context is read only, and only `access_type` can
/// be read with a narrow load.
fn cgroup_dev_is_valid_access(off: u32, size: u32, t: Access) -> bool {
    use crate::prog::bpf_cgroup_dev_ctx::*;
    if t == Access::Write || off + size > SIZE {
        return false;
    }
    if off < MAJOR {
        return size <= 4;
    }
    size == 4
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::insn::asm::*;
    use crate::map::{BpfMap, MapAttr, map_alloc};

    fn array_map() -> Arc<BpfMap> {
        array_map_of(4)
    }

    fn array_map_of(max_entries: u32) -> Arc<BpfMap> {
        let attr = MapAttr {
            map_type: BPF_MAP_TYPE_ARRAY,
            key_size: 4,
            value_size: 8,
            max_entries,
            map_flags: 0,
            numa_node: 0,
        };
        let ops = map_alloc(&attr, 1, u64::MAX).unwrap();
        Arc::new(BpfMap::new(&attr, [0; 16], 1, ops))
    }

    fn check(insns: &[BpfInsn], caps: bool) -> (Result<Verified>, String) {
        check_with(insns, caps, array_map(), None)
    }

    /// Checks with the map `map` at descriptor 3 and the loader's `fd_array`.
    fn check_with(
        insns: &[BpfInsn],
        caps: bool,
        map: Arc<BpfMap>,
        fd_array: Option<&dyn Fn(u32) -> Result<i32>>,
    ) -> (Result<Verified>, String) {
        let opts = VerifierOpts {
            prog_type: BPF_PROG_TYPE_SOCKET_FILTER,
            expected_attach_type: 0,
            bpf_capable: caps,
            allow_ptr_leaks: caps,
            strict_alignment: false,
        };
        let mut log = BpfVerifierLog::new(1);
        let r = bpf_check(
            insns.to_vec(),
            &opts,
            &|fd| if fd == 3 { Ok(map.clone()) } else { Err(Errno::EBADF) },
            fd_array,
            &mut log,
        );
        (r, log.text)
    }

    fn ld_map(dst: u8) -> [BpfInsn; 2] {
        ld_imm64(dst, BPF_PSEUDO_MAP_FD, 3)
    }

    fn concat(parts: &[&[BpfInsn]]) -> Vec<BpfInsn> {
        parts.iter().flat_map(|p| p.iter().copied()).collect()
    }

    fn prog_array() -> Arc<BpfMap> {
        let attr = MapAttr {
            map_type: BPF_MAP_TYPE_PROG_ARRAY,
            key_size: 4,
            value_size: 4,
            max_entries: 2,
            map_flags: 0,
            numa_node: 0,
        };
        let ops = map_alloc(&attr, 1, u64::MAX).unwrap();
        Arc::new(BpfMap::new(&attr, [0; 16], 1, ops))
    }

    #[test]
    fn a_tail_call_needs_a_program_array() {
        use crate::helpers::func::BPF_FUNC_map_lookup_elem;
        let tail = concat(&[
            &ld_map(2),
            &[mov64_imm(3, 0), call(BPF_FUNC_tail_call), mov64_imm(0, 0), exit()],
        ]);
        let (r, log) = check_with(&tail, false, prog_array(), None);
        assert!(r.is_ok(), "{log}");
        // R0 is not set after a tail call.
        let mut p = tail.clone();
        p.remove(4);
        let (r, log) = check_with(&p, false, prog_array(), None);
        assert_eq!(r.err(), Some(Errno::EACCES));
        assert!(log.contains("R0 !read_ok"), "{log}");
        let (r, log) = check(&tail, false);
        assert_eq!(r.err(), Some(Errno::EINVAL));
        assert!(log.contains("cannot pass map_type 2 into func bpf_tail_call#12\n"), "{log}");
        let lookup = concat(&[
            &ld_map(1),
            &[
                mov64_reg(2, BPF_REG_FP),
                alu64_imm(BPF_ADD, 2, -8),
                st_mem(BPF_DW, 2, 0, 0),
                call(BPF_FUNC_map_lookup_elem),
                mov64_imm(0, 0),
                exit(),
            ],
        ]);
        let (r, log) = check_with(&lookup, false, prog_array(), None);
        assert_eq!(r.err(), Some(Errno::EINVAL));
        assert!(log.contains("cannot pass map_type 3 into func bpf_map_lookup_elem#1\n"), "{log}");
        // A program with functions cannot use tail calls without a JIT.
        let mixed = concat(&[
            &[mov64_reg(6, 1), call_local(7), mov64_reg(1, 6)],
            &ld_map(2),
            &[mov64_imm(3, 0), call(BPF_FUNC_tail_call), mov64_imm(0, 0), exit()],
            &[mov64_imm(0, 0), exit()],
        ]);
        let (r, log) = check_with(&mixed, true, prog_array(), None);
        assert_eq!(r.err(), Some(Errno::EINVAL));
        assert!(
            log.contains("mixing of tail_calls and bpf-to-bpf calls is not supported\n"),
            "{log}"
        );
    }

    /// The program of bpf_prog01 of LTP.
    fn prog01() -> Vec<BpfInsn> {
        concat(&[
            &ld_map(1),
            &[
                mov64_reg(2, BPF_REG_FP),
                alu64_imm(BPF_ADD, 2, -8),
                st_mem(BPF_DW, 2, 0, 0),
                call(crate::helpers::func::BPF_FUNC_map_lookup_elem),
                jmp_imm(BPF_JEQ, 0, 0, 3),
                mov64_reg(1, 0),
                st_mem(BPF_DW, 1, 0, 1),
                mov64_imm(0, 0),
                exit(),
            ],
        ])
    }

    #[test]
    fn bpf_prog01_is_accepted() {
        let (r, log) = check(&prog01(), false);
        let v = r.unwrap();
        assert_eq!(v.used_maps.len(), 1);
        assert_eq!(v.insns[0].imm, 0);
        assert!(log.contains("processed"));
    }

    #[test]
    fn a_store_without_a_null_check_is_refused() {
        let mut p = prog01();
        // Remove the NULL check.
        p[6] = mov64_imm(3, 0);
        let (r, log) = check(&p, false);
        assert_eq!(r.err(), Some(Errno::EACCES));
        assert!(log.contains("R1 invalid mem access 'map_value_or_null'"), "{log}");
    }

    /// The program of bpf_prog03 of LTP, CVE-2017-16995.
    #[test]
    fn cve_2017_16995_is_refused() {
        let p = concat(&[
            &ld_map(1),
            &[
                mov64_reg(8, BPF_REG_FP),
                alu64_imm(BPF_ADD, 8, -4),
                mov32_imm(2, 0),
                stx_mem(BPF_W, 8, 2, 0),
                mov64_reg(2, 8),
                call(crate::helpers::func::BPF_FUNC_map_lookup_elem),
                jmp_imm(BPF_JNE, 0, 0, 2),
                mov64_reg(0, 0),
                exit(),
                mov32_imm(1, -1),
                alu64_imm(BPF_ADD, 1, 1),
                alu64_imm(BPF_RSH, 1, 26),
                stx_mem(BPF_DW, 0, 1, 0),
                mov64_reg(2, 0),
                alu64_reg(BPF_SUB, 2, 1),
                mov64_imm(3, 0xdead),
                stx_mem(BPF_DW, 2, 3, 0),
                mov32_imm(0, 0),
                exit(),
            ],
        ]);
        let (r, log) = check(&p, true);
        assert_eq!(r.err(), Some(Errno::EACCES));
        assert!(log.contains("invalid access to map value"), "{log}");
    }

    /// The program of bpf_prog04 of LTP, CVE-2018-18445.
    #[test]
    fn cve_2018_18445_is_refused() {
        let p = concat(&[
            &[
                mov64_imm(8, 2),
                alu64_imm(BPF_LSH, 8, 31),
                alu32_imm(BPF_RSH, 8, 31),
                alu32_imm(BPF_SUB, 8, 2),
            ],
            &ld_map(1),
            &[
                mov64_reg(2, BPF_REG_FP),
                alu64_imm(BPF_ADD, 2, -4),
                st_mem(BPF_W, 2, 0, 0),
                call(crate::helpers::func::BPF_FUNC_map_lookup_elem),
                jmp_imm(BPF_JNE, 0, 0, 1),
                exit(),
                alu64_reg(BPF_ADD, 0, 8),
                stx_mem(BPF_DW, 0, 8, 0),
                mov64_imm(0, 0),
                exit(),
            ],
        ]);
        let (r, log) = check(&p, true);
        assert_eq!(r.err(), Some(Errno::EACCES));
        assert!(log.contains("out of bounds"), "{log}");
    }

    #[test]
    fn a_bounded_variable_offset_is_accepted() {
        // r0 = map value; r1 = *(u8 *)(ctx + 0) & 7 ... the value has 8 bytes, so a byte
        // store at r0 + (r1 & 7) is in bounds, and at r0 + (r1 & 15) it is not.
        let body = |mask: i32| {
            concat(&[
                &[mov64_reg(6, 1)],
                &ld_map(1),
                &[
                    mov64_reg(2, BPF_REG_FP),
                    alu64_imm(BPF_ADD, 2, -4),
                    st_mem(BPF_W, 2, 0, 0),
                    call(crate::helpers::func::BPF_FUNC_map_lookup_elem),
                    jmp_imm(BPF_JEQ, 0, 0, 4),
                    ldx_mem(BPF_W, 1, 6, 0),
                    alu64_imm(BPF_AND, 1, mask),
                    alu64_reg(BPF_ADD, 0, 1),
                    st_mem(BPF_B, 0, 0, 1),
                    mov64_imm(0, 0),
                    exit(),
                ],
            ])
        };
        assert!(check(&body(7), false).0.is_ok());
        let (r, log) = check(&body(15), false);
        assert_eq!(r.err(), Some(Errno::EACCES));
        assert!(log.contains("invalid access to map value"), "{log}");
    }

    #[test]
    fn a_bounds_check_with_a_jump_is_accepted() {
        // if (r1 > 7) exit; *(u8 *)(r0 + r1) = 1.
        let p = concat(&[
            &[mov64_reg(6, 1)],
            &ld_map(1),
            &[
                mov64_reg(2, BPF_REG_FP),
                alu64_imm(BPF_ADD, 2, -4),
                st_mem(BPF_W, 2, 0, 0),
                call(crate::helpers::func::BPF_FUNC_map_lookup_elem),
                jmp_imm(BPF_JEQ, 0, 0, 4),
                ldx_mem(BPF_W, 1, 6, 0),
                jmp_imm(BPF_JGT, 1, 7, 2),
                alu64_reg(BPF_ADD, 0, 1),
                st_mem(BPF_B, 0, 0, 1),
                mov64_imm(0, 0),
                exit(),
            ],
        ]);
        let (r, log) = check(&p, false);
        assert!(r.is_ok(), "{log}");
    }

    #[test]
    fn loops_dead_code_and_bad_jumps_are_refused() {
        let (r, log) = check(&[mov64_imm(0, 0), jmp_imm(BPF_JA, 0, 0, -2), exit()], false);
        assert_eq!(r.err(), Some(Errno::EINVAL));
        assert!(log.contains("back-edge from insn 1 to 0"), "{log}");
        // With `CAP_BPF` a loop is allowed, but it must end.
        let (r, log) = check(&[mov64_imm(0, 0), jmp_imm(BPF_JEQ, 0, 0, -2), exit()], true);
        assert_eq!(r.err(), Some(Errno::EINVAL));
        assert!(log.contains("infinite loop detected at insn 0"), "{log}");
        let p = [mov64_imm(0, 0), alu64_imm(BPF_ADD, 0, 1), jmp_imm(BPF_JNE, 0, 0, -2), exit()];
        let (r, log) = check(&p, true);
        assert_eq!(r.err(), Some(Errno::E2BIG));
        assert!(log.contains("BPF program is too large. Processed 1000001 insn"), "{log}");
        // "jump test 4" of test_verifier: 2^36 paths with the same state. The pruning checks
        // each instruction once.
        let mut p = Vec::new();
        for i in 0..36 {
            p.push(jmp_imm(BPF_JEQ, 1, 10, i % 4 + 1));
        }
        p.extend([jmp_imm(BPF_JEQ, 1, 10, 0); 4]);
        p.extend([mov64_imm(0, 0), exit()]);
        let (r, log) = check(&p, true);
        assert!(r.is_ok(), "{log}");
        let p = [mov64_imm(0, 0), alu64_imm(BPF_ADD, 0, 1), jmp_imm(BPF_JLT, 0, 10, -2), exit()];
        let (r, log) = check(&p, true);
        assert!(r.is_ok(), "{log}");
        // The back edge of a branch that is never taken, from "dead code: start" of
        // test_verifier.
        let p = [
            jmp_imm(BPF_JA, 0, 0, 2),
            BpfInsn {
                code: BPF_LDX | BPF_MEM | BPF_B,
                dst_reg: 8,
                src_reg: 9,
                ..BpfInsn::default()
            },
            jmp_imm(BPF_JA, 0, 0, 2),
            mov64_imm(0, 7),
            jmp_imm(BPF_JGE, 0, 10, -4),
            exit(),
        ];
        let (r, log) = check(&p, true);
        assert!(r.is_ok(), "{log}");
        let (r, log) = check(&[mov64_imm(0, 0), exit(), exit()], true);
        assert_eq!(r.err(), Some(Errno::EINVAL));
        assert!(log.contains("unreachable insn 2"), "{log}");
        let (r, log) = check(&[mov64_imm(0, 0), jmp_imm(BPF_JA, 0, 0, 5), exit()], true);
        assert_eq!(r.err(), Some(Errno::EINVAL));
        assert!(log.contains("jump out of range"), "{log}");
        let (r, log) = check(&[mov64_imm(0, 0)], true);
        assert_eq!(r.err(), Some(Errno::EINVAL));
        assert!(log.contains("last insn is not an exit or jmp"), "{log}");
    }

    #[test]
    fn registers_and_the_stack_must_be_set() {
        let (r, log) = check(&[exit()], true);
        assert_eq!(r.err(), Some(Errno::EACCES));
        assert!(log.contains("R0 !read_ok"), "{log}");
        let (r, log) = check(&[ldx_mem(BPF_DW, 0, BPF_REG_FP, -8), exit()], false);
        assert_eq!(r.err(), Some(Errno::EACCES));
        assert!(log.contains("invalid read from stack"), "{log}");
        // With `CAP_PERFMON`, the read gives an unknown value.
        assert!(check(&[ldx_mem(BPF_DW, 0, BPF_REG_FP, -8), exit()], true).0.is_ok());
        let (r, log) = check(&[mov64_imm(BPF_REG_FP, 0), mov64_imm(0, 0), exit()], true);
        assert_eq!(r.err(), Some(Errno::EACCES));
        assert!(log.contains("frame pointer is read only"), "{log}");
        // The stack of bpf_prog05 of LTP: fp + (-1) is a known offset.
        let p = [
            mov64_reg(2, BPF_REG_FP),
            mov64_imm(3, -1),
            alu64_reg(BPF_ADD, 2, 3),
            st_mem(BPF_B, 2, 0, 0),
            mov64_imm(0, 0),
            exit(),
        ];
        assert!(check(&p, true).0.is_ok());
    }

    #[test]
    fn pointers_do_not_leak_without_caps() {
        // Return the frame pointer.
        let (r, log) = check(&[mov64_reg(0, BPF_REG_FP), exit()], false);
        assert_eq!(r.err(), Some(Errno::EACCES));
        assert!(log.contains("R0 leaks addr as return value"), "{log}");
        // Store the context pointer in a map value.
        let mut p = prog01();
        p[8] = stx_mem(BPF_DW, 1, 6, 0);
        p.insert(0, mov64_reg(6, 1));
        let p: Vec<BpfInsn> = p;
        let (r, log) = check(&p, false);
        assert_eq!(r.err(), Some(Errno::EACCES));
        assert!(log.contains("leaks addr into map"), "{log}");
    }

    #[test]
    fn the_context_rules_of_a_socket_filter() {
        // A read of len and a write of cb[0] are allowed.
        let ok = [
            ldx_mem(BPF_W, 0, 1, sk_buff::LEN as i16),
            stx_mem(BPF_W, 1, 0, sk_buff::CB as i16),
            ldx_mem(BPF_B, 0, 1, sk_buff::PROTOCOL as i16),
            exit(),
        ];
        assert!(check(&ok, false).0.is_ok());
        // A write of mark is not.
        let (r, log) =
            check(&[mov64_imm(0, 0), stx_mem(BPF_W, 1, 0, sk_buff::MARK as i16), exit()], false);
        assert_eq!(r.err(), Some(Errno::EACCES));
        assert!(log.contains("invalid bpf_context access off=8 size=4"), "{log}");
        // A read of data is not.
        let (r, _) = check(&[ldx_mem(BPF_W, 0, 1, 76), exit()], false);
        assert_eq!(r.err(), Some(Errno::EACCES));
    }

    #[test]
    fn helpers_check_their_arguments() {
        // An unknown helper.
        let (r, log) = check(&[call(9999), mov64_imm(0, 0), exit()], true);
        assert_eq!(r.err(), Some(Errno::EINVAL));
        assert!(log.contains("invalid func"), "{log}");
        // The key is not set.
        let p = concat(&[
            &ld_map(1),
            &[
                mov64_reg(2, BPF_REG_FP),
                alu64_imm(BPF_ADD, 2, -4),
                call(crate::helpers::func::BPF_FUNC_map_lookup_elem),
                mov64_imm(0, 0),
                exit(),
            ],
        ]);
        let (r, log) = check(&p, false);
        assert_eq!(r.err(), Some(Errno::EACCES));
        assert!(log.contains("invalid indirect read from stack"), "{log}");
        assert!(check(&p, true).0.is_ok());
        // A bad map descriptor.
        let p = concat(&[&ld_imm64(1, BPF_PSEUDO_MAP_FD, 9), &[mov64_imm(0, 0), exit()]]);
        let (r, log) = check(&p, true);
        assert_eq!(r.err(), Some(Errno::EBADF));
        assert!(log.contains("fd 9 is not pointing to valid bpf_map"), "{log}");
    }

    #[test]
    fn bad_instructions_are_refused() {
        let (r, log) = check(&[BpfInsn { code: 0xff, ..BpfInsn::default() }, exit()], true);
        assert_eq!(r.err(), Some(Errno::EINVAL));
        assert!(log.contains("unknown opcode ff"), "{log}");
        let (r, log) = check(&[mov64_imm(0, 1), alu64_imm(BPF_DIV, 0, 0), exit()], true);
        assert_eq!(r.err(), Some(Errno::EINVAL));
        assert!(log.contains("div by zero"), "{log}");
        let (r, log) = check(&[mov64_imm(0, 1), alu64_imm(BPF_LSH, 0, 64), exit()], true);
        assert_eq!(r.err(), Some(Errno::EINVAL));
        assert!(log.contains("invalid shift 64"), "{log}");
    }

    /// `BPF_RAND_UEXT_R7` of test_verifier: R7 is a random value of 31 bits.
    fn rand_uext_r7() -> [BpfInsn; 4] {
        [
            call(crate::helpers::func::BPF_FUNC_get_prandom_u32),
            mov64_reg(7, 0),
            alu64_imm(BPF_LSH, 7, 33),
            alu64_imm(BPF_RSH, 7, 33),
        ]
    }

    /// The load from R9, which is not set, that test_verifier puts on a path that must be dead.
    fn bad_load() -> BpfInsn {
        ldx_mem(BPF_B, 8, 9, 0)
    }

    fn jmp32_imm(op: u8, dst: u8, imm: i32, off: i16) -> BpfInsn {
        BpfInsn { code: BPF_JMP32 | op | BPF_K, ..jmp_imm(op, dst, imm, off) }
    }

    #[test]
    fn jset_and_jmp32_refine_the_bounds() {
        // "jset: range" of test_verifier.
        let p = [
            call(crate::helpers::func::BPF_FUNC_get_prandom_u32),
            mov64_reg(1, 0),
            mov64_imm(0, 0),
            alu64_imm(BPF_AND, 1, 0xff),
            jmp_imm(BPF_JSET, 1, 0xf0, 3),
            jmp_imm(BPF_JLT, 1, 0x10, 1),
            bad_load(),
            exit(),
            jmp_imm(BPF_JSET, 1, 0x10, 1),
            exit(),
            jmp_imm(BPF_JGE, 1, 0x10, 1),
            bad_load(),
            exit(),
        ];
        let (r, log) = check(&p, true);
        assert!(r.is_ok(), "{log}");
        // "jset32: min/max deduction" and "jne32: min/max deduction".
        let jset32 = concat(&[
            &rand_uext_r7(),
            &[
                mov64_imm(0, 0),
                jmp32_imm(BPF_JSET, 7, 0x10, 1),
                exit(),
                jmp32_imm(BPF_JGE, 7, 0x10, 1),
                bad_load(),
                exit(),
            ],
        ]);
        let (r, log) = check(&jset32, true);
        assert!(r.is_ok(), "{log}");
        let jne32 = concat(&[
            &rand_uext_r7(),
            &[
                mov64_imm(0, 0),
                jmp32_imm(BPF_JNE, 7, 0x10, 1),
                jmp_imm(BPF_JNE, 7, 0x10, 1),
                exit(),
                bad_load(),
                exit(),
            ],
        ]);
        let (r, log) = check(&jne32, true);
        assert!(r.is_ok(), "{log}");
        // The upper half of an unknown value can be set, so JMP32 tells nothing about JMP.
        let p = [
            call(crate::helpers::func::BPF_FUNC_get_prandom_u32),
            mov64_reg(7, 0),
            alu64_imm(BPF_LSH, 7, 1),
            mov64_imm(0, 0),
            jmp32_imm(BPF_JNE, 7, 0x10, 1),
            jmp_imm(BPF_JNE, 7, 0x10, 1),
            exit(),
            bad_load(),
            exit(),
        ];
        let (r, log) = check(&p, true);
        assert_eq!(r.err(), Some(Errno::EACCES));
        assert!(log.contains("R9 !read_ok"), "{log}");
    }

    #[test]
    fn the_order_of_the_errors_is_as_in_linux() {
        // "junk insn5": the reserved fields of an ALU instruction come before the registers.
        let junk = BpfInsn { code: 0x7f, dst_reg: 15, src_reg: 15, off: -1, imm: -1 };
        let (r, log) = check(&[junk, exit()], true);
        assert_eq!(r.err(), Some(Errno::EINVAL));
        assert!(log.contains("BPF_ALU uses reserved fields"), "{log}");
        // "test1 ld_imm64": the log gives the first half of the 64-bit load.
        let p = concat(&[
            &[jmp_imm(BPF_JEQ, 1, 0, 1)],
            &ld_imm64(0, 0, 0),
            &ld_imm64(0, 0, 1),
            &[exit()],
        ]);
        let (r, log) = check(&p, true);
        assert_eq!(r.err(), Some(Errno::EINVAL));
        assert!(log.contains("jump into the middle of ldimm64 insn 1"), "{log}");
    }

    #[test]
    fn sock_addr_access() {
        use crate::prog::bpf_sock_addr::*;
        let v4 = BPF_CGROUP_INET4_CONNECT;
        let v6 = BPF_CGROUP_INET6_BIND;
        assert!(sock_addr_is_valid_access(USER_IP4, 4, Access::Write, v4));
        assert!(sock_addr_is_valid_access(USER_IP4 + 2, 2, Access::Read, v4));
        assert!(!sock_addr_is_valid_access(USER_IP4, 2, Access::Write, v4));
        assert!(!sock_addr_is_valid_access(USER_IP6, 4, Access::Read, v4));
        assert!(sock_addr_is_valid_access(USER_IP6, 8, Access::Write, v6));
        let send6 = BPF_CGROUP_UDP6_SENDMSG;
        assert!(sock_addr_is_valid_access(MSG_SRC_IP6 + 4, 8, Access::Read, send6));
        assert!(!sock_addr_is_valid_access(MSG_SRC_IP6 + 12, 8, Access::Read, send6));
        assert!(!sock_addr_is_valid_access(MSG_SRC_IP6 + 12, 8, Access::Write, send6));
        assert!(!sock_addr_is_valid_access(USER_IP4, 4, Access::Read, v6));
        assert!(sock_addr_is_valid_access(USER_PORT, 4, Access::Write, v6));
        assert!(!sock_addr_is_valid_access(FAMILY, 4, Access::Write, v6));
        assert!(!sock_addr_is_valid_access(MSG_SRC_IP4, 4, Access::Read, v4));
        assert!(!sock_addr_is_valid_access(SK, 8, Access::Read, v4));
    }

    #[test]
    fn calls_of_functions_of_the_program() {
        // main calls f(5), and f returns its argument + 1.
        let p = [
            mov64_imm(1, 5),
            call_local(1),
            exit(),
            mov64_reg(0, 1),
            alu64_imm(BPF_ADD, 0, 1),
            exit(),
        ];
        let (r, log) = check(&p, true);
        assert!(r.is_ok(), "{log}");
        // Only a loader with CAP_BPF can call a function.
        let (r, log) = check(&p, false);
        assert_eq!(r.err(), Some(Errno::EPERM));
        assert!(log.contains("loading/calling other bpf or kernel functions are allowed"), "{log}");
        // The call clears R1 to R5 of the caller.
        let q = [mov64_imm(1, 5), call_local(2), mov64_reg(0, 1), exit(), mov64_reg(0, 1), exit()];
        let (r, log) = check(&q, true);
        assert_eq!(r.err(), Some(Errno::EACCES));
        assert!(log.contains("R1 !read_ok"), "{log}");
        // The function does not get R6 of the caller.
        let q = [mov64_imm(6, 1), call_local(1), exit(), mov64_reg(0, 6), exit()];
        let (r, log) = check(&q, true);
        assert_eq!(r.err(), Some(Errno::EACCES));
        assert!(log.contains("R6 !read_ok"), "{log}");
        // A destination that is not an instruction.
        let (r, log) = check(&[call_local(5), exit()], true);
        assert_eq!(r.err(), Some(Errno::EINVAL));
        assert!(log.contains("call to invalid destination"), "{log}");
        // A jump out of its function.
        let q = [mov64_imm(0, 0), call_local(1), exit(), jmp_imm(BPF_JA, 0, 0, -2), exit()];
        let (r, log) = check(&q, true);
        assert_eq!(r.err(), Some(Errno::EINVAL));
        assert!(log.contains("jump out of range from insn 3 to 2"), "{log}");
        // A kernel function needs BTF.
        let kfunc = BpfInsn { src_reg: BPF_PSEUDO_KFUNC_CALL, ..call(1) };
        let (r, log) = check(&[kfunc, mov64_imm(0, 0), exit()], true);
        assert_eq!(r.err(), Some(ENOTSUPP));
        assert!(log.contains("without CONFIG_DEBUG_INFO_BTF"), "{log}");
    }

    #[test]
    fn functions_and_the_stack_of_the_caller() {
        // f reads the stack of main through a pointer.
        let p = [
            st_mem(BPF_DW, BPF_REG_FP, -8, 7),
            mov64_reg(1, BPF_REG_FP),
            alu64_imm(BPF_ADD, 1, -8),
            call_local(1),
            exit(),
            ldx_mem(BPF_DW, 0, 1, 0),
            exit(),
        ];
        let (r, log) = check(&p, true);
        assert!(r.is_ok(), "{log}");
        // f writes its frame pointer in the stack of main.
        let mut q = p.to_vec();
        q[5] = stx_mem(BPF_DW, 1, BPF_REG_FP, 0);
        q.insert(6, mov64_imm(0, 0));
        let (r, log) = check(&q, true);
        assert_eq!(r.err(), Some(Errno::EINVAL));
        assert!(
            log.contains("cannot spill pointers to stack into stack frame of the caller"),
            "{log}"
        );
        // f returns its frame pointer.
        let q = [call_local(1), exit(), mov64_reg(0, BPF_REG_FP), exit()];
        let (r, log) = check(&q, true);
        assert_eq!(r.err(), Some(Errno::EINVAL));
        assert!(log.contains("cannot return stack pointer to the caller"), "{log}");
        // The stack of main and f is more than 512 bytes.
        let q = [
            st_mem(BPF_DW, BPF_REG_FP, -512, 0),
            call_local(1),
            exit(),
            st_mem(BPF_DW, BPF_REG_FP, -8, 0),
            mov64_imm(0, 0),
            exit(),
        ];
        let (r, log) = check(&q, true);
        assert_eq!(r.err(), Some(Errno::EACCES));
        assert!(log.contains("combined stack size of 2 calls is 544. Too large"), "{log}");
    }

    #[test]
    fn recursion_and_deep_calls_are_refused() {
        // As on Linux, recursion stops at the limit of the frames.
        let (r, log) = check(&[call_local(1), exit(), call_local(-1), exit()], true);
        assert_eq!(r.err(), Some(Errno::E2BIG));
        assert!(log.contains("the call stack of 9 frames is too deep"), "{log}");
        // A chain of `n` functions after main.
        let chain = |n: usize| {
            let mut p = Vec::new();
            for _ in 0..n {
                p.extend([call_local(1), exit()]);
            }
            p.extend([mov64_imm(0, 0), exit()]);
            p
        };
        let (r, log) = check(&chain(7), true);
        assert!(r.is_ok(), "{log}");
        let (r, log) = check(&chain(8), true);
        assert_eq!(r.err(), Some(Errno::E2BIG));
        assert!(log.contains("the call stack of 9 frames is too deep"), "{log}");
    }

    #[test]
    fn packet_loads_of_a_socket_filter() {
        let p = [mov64_reg(6, 1), ld_abs(BPF_H, 12), mov64_imm(2, 1), ld_ind(BPF_B, 2, 0), exit()];
        let (r, log) = check(&p, false);
        assert!(r.is_ok(), "{log}");
        // R6 must be the context.
        let (r, log) = check(&[mov64_imm(6, 0), ld_abs(BPF_B, 0), exit()], false);
        assert_eq!(r.err(), Some(Errno::EINVAL));
        assert!(log.contains("at the time of BPF_LD_ABS|IND R6 != pointer to skb"), "{log}");
        // The load clears R1 to R5.
        let (r, log) = check(&[mov64_reg(6, 1), ld_abs(BPF_B, 0), mov64_reg(0, 1), exit()], false);
        assert_eq!(r.err(), Some(Errno::EACCES));
        assert!(log.contains("R1 !read_ok"), "{log}");
        // A load of 8 bytes is not an instruction.
        let (r, log) = check(&[mov64_reg(6, 1), ld_abs(BPF_DW, 0), exit()], false);
        assert_eq!(r.err(), Some(Errno::EINVAL));
        assert!(log.contains("unknown opcode 38"), "{log}");
        let (r, log) =
            check(&[mov64_reg(6, 1), ld_abs(BPF_B, 0), ld_ind(BPF_W, 2, 0), exit()], false);
        assert_eq!(r.err(), Some(Errno::EACCES));
        assert!(log.contains("R2 !read_ok"), "{log}");
        // Only in the main program.
        let q = [mov64_reg(6, 1), call_local(1), exit(), ld_abs(BPF_B, 0), exit()];
        let (r, log) = check(&q, true);
        assert_eq!(r.err(), Some(Errno::EINVAL));
        assert!(log.contains("LD_ABS is not allowed in subprogs without BTF"), "{log}");
        let q = [
            call_local(1),
            exit(),
            call(crate::helpers::func::BPF_FUNC_tail_call),
            mov64_imm(0, 0),
            exit(),
        ];
        let (r, log) = check(&q, true);
        assert_eq!(r.err(), Some(Errno::EINVAL));
        assert!(log.contains("tail_call is not allowed in subprogs without BTF"), "{log}");
    }

    #[test]
    fn direct_loads_of_a_map_value() {
        // R1 = &value[0] + 4, and a read of 4 bytes there.
        let mut p = ld_imm64(1, BPF_PSEUDO_MAP_VALUE, 3).to_vec();
        p[1].imm = 4;
        p.extend([ldx_mem(BPF_W, 0, 1, 0), exit()]);
        let (r, log) = check_with(&p, true, array_map_of(1), None);
        let v = r.unwrap_or_else(|e| panic!("{e:?} {log}"));
        assert_eq!(v.insns[0].src_reg, BPF_PSEUDO_MAP_VALUE);
        assert_eq!(v.insns[0].imm, 0);
        // A read of 8 bytes there is out of the value.
        let mut q = p.clone();
        q[2] = ldx_mem(BPF_DW, 0, 1, 0);
        let (r, log) = check_with(&q, true, array_map_of(1), None);
        assert_eq!(r.err(), Some(Errno::EACCES));
        assert!(log.contains("invalid access to map value"), "{log}");
        // An array of more than one value has no fixed address.
        let (r, log) = check_with(&p, true, array_map_of(4), None);
        assert_eq!(r.err(), Some(Errno::EOPNOTSUPP));
        assert!(log.contains("invalid access to map value pointer, value_size=8 off=4"), "{log}");
        // The offset is out of the value.
        let mut q = p.clone();
        q[1].imm = 8;
        let (r, _) = check_with(&q, true, array_map_of(1), None);
        assert_eq!(r.err(), Some(Errno::EINVAL));
        // The map is an index in fd_array.
        let mut q = p.clone();
        q[0].src_reg = BPF_PSEUDO_MAP_IDX_VALUE;
        q[0].imm = 2;
        let (r, log) = check_with(&q, true, array_map_of(1), None);
        assert_eq!(r.err(), Some(Errno::EPROTO));
        assert!(log.contains("fd_idx without fd_array is invalid"), "{log}");
        let fds = |i: u32| if i == 2 { Ok(3) } else { Err(Errno::EFAULT) };
        let (r, log) = check_with(&q, true, array_map_of(1), Some(&fds));
        let v = r.unwrap_or_else(|e| panic!("{e:?} {log}"));
        assert_eq!(v.insns[0].src_reg, BPF_PSEUDO_MAP_VALUE);
        // A map load with a value in the second half is wrong.
        let mut q = ld_map(1).to_vec();
        q[1].imm = 1;
        q.extend([mov64_imm(0, 0), exit()]);
        let (r, log) = check(&q, true);
        assert_eq!(r.err(), Some(Errno::EINVAL));
        assert!(log.contains("unrecognized bpf_ld_imm64 insn"), "{log}");
    }
}
