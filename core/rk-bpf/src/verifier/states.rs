//! The pruning of `do_check`: the liveness of the registers, `compute_live_registers` of
//! Linux, and the lists of the explored states, `is_state_visited` and `states_equal` of Linux.
//!
//! A state that `do_check` explored to each exit is safe. When a new state at the same
//! instruction is within the safe state, each path from the new state is a path of the safe
//! state, so the new path stops. The new state is within the old state when each register and
//! each slot of the stack that the program can read is within its old value, `regsafe` and
//! `stacksafe` of Linux. A register that the program writes before it reads it is not live,
//! and `clean` forgets its value, so it does not make two states different.
//!
//! The verifier has no precision tracking, so each scalar is precise: the bounds and the tnum
//! of the new scalar must be within those of the old scalar.

use super::{Reg, RegType, STACK_INVALID, STACK_MISC, STACK_SPILL, StackSlot, State, successors};
use crate::insn::*;
use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

/// The most bytes of the kept states. A state with a small stack uses about 1 KiB, so the lists
/// keep thousands of states.
const MAX_KEPT_BYTES: usize = 16 << 20;
/// The most states of one instruction for a loader without `CAP_BPF`,
/// `BPF_COMPLEXITY_LIMIT_STATES` of Linux.
const BPF_COMPLEXITY_LIMIT_STATES: usize = 64;

/// R0, the return value.
const R0: u16 = 1;
/// R1 to R5, the arguments of a call.
const ARGS: u16 = 0b11_1110;
/// R0 to R5, the registers that a call clobbers, `CALLER_SAVED_REGS` of Linux.
const CALLER_SAVED: u16 = 0b11_1111;
/// R0 to R9. The frame pointer R10 is always live.
const ALL: u16 = (1 << BPF_REG_FP) - 1;

/// The bit of the register `regno`.
fn bit(regno: u8) -> u16 {
    if (regno as usize) < MAX_BPF_REG { 1 << regno } else { 0 }
}

/// The registers that the instruction `i` reads, and the registers that it always writes, as
/// `compute_insn_live_regs` of Linux. When the verifier does not know an instruction, it reads
/// each register, so that the instruction does not change the liveness.
fn use_def(insns: &[BpfInsn], i: usize) -> (u16, u16) {
    let insn = insns[i];
    let (dst, src) = (bit(insn.dst_reg), bit(insn.src_reg));
    let x = if bpf_src(insn.code) == BPF_X { src } else { 0 };
    match bpf_class(insn.code) {
        BPF_ALU | BPF_ALU64 => match bpf_op(insn.code) {
            BPF_MOV => (x, dst),
            BPF_NEG | BPF_END => (dst, dst),
            _ => (dst | x, dst),
        },
        BPF_LDX => (src, dst),
        BPF_ST => (dst, 0),
        // An atomic instruction can read R0 and write R0 or the source. It writes nothing for
        // the liveness, so the registers stay live.
        BPF_STX if bpf_mode(insn.code) == BPF_ATOMIC => (dst | src | R0, 0),
        BPF_STX => (dst | src, 0),
        BPF_LD if insn.is_ld_imm64() => (0, dst),
        // `check_ld_abs`: the context is in R6.
        BPF_LD if bpf_mode(insn.code) == BPF_ABS => (bit(6), CALLER_SAVED),
        BPF_LD if bpf_mode(insn.code) == BPF_IND => (bit(6) | src, CALLER_SAVED),
        BPF_JMP | BPF_JMP32 => match bpf_op(insn.code) {
            BPF_JA => (0, 0),
            BPF_EXIT => (R0, 0),
            BPF_CALL => (ARGS, CALLER_SAVED),
            _ => (dst | x, 0),
        },
        _ => (ALL, 0),
    }
}

/// The registers that are live before each instruction, `compute_live_registers` of Linux: a
/// register is live when a path from the instruction can read it before it writes it. A call of
/// a function of the program goes on at the next instruction, and the function has its own
/// liveness. `check_cfg` checked the jumps.
pub(super) fn live_regs(insns: &[BpfInsn]) -> Vec<u16> {
    let n = insns.len();
    let mut half = vec![false; n];
    let mut i = 0;
    while i < n {
        if insns[i].is_ld_imm64() && i + 1 < n {
            half[i + 1] = true;
            i += 2;
        } else {
            i += 1;
        }
    }
    let ud: Vec<(u16, u16)> =
        (0..n).map(|i| if half[i] { (0, 0) } else { use_def(insns, i) }).collect();
    let mut live = vec![0u16; n];
    loop {
        let mut changed = false;
        for i in (0..n).rev() {
            if half[i] {
                continue;
            }
            let mut succ = successors(insns, i);
            let insn = insns[i];
            if bpf_class(insn.code) == BPF_JMP
                && bpf_op(insn.code) == BPF_CALL
                && insn.src_reg == BPF_PSEUDO_CALL
            {
                succ[1] = None;
            }
            let mut out = 0;
            for s in succ.into_iter().flatten() {
                if (0..n as i64).contains(&s) {
                    out |= live[s as usize];
                }
            }
            let new = ud[i].0 | (out & !ud[i].1);
            if new != live[i] {
                live[i] = new;
                changed = true;
            }
        }
        if !changed {
            return live;
        }
    }
}

/// Forgets the registers that are not live, `clean_live_states` of Linux. The frame that runs
/// now is at the instruction `pc`, and a caller goes on after its call.
pub(super) fn clean(st: &mut State, pc: usize, live: &[u16]) {
    let forget = |regs: &mut [Reg; MAX_BPF_REG], mask: u16| {
        for (r, reg) in regs.iter_mut().enumerate().take(BPF_REG_FP as usize) {
            if mask & (1 << r) == 0 {
                *reg = Reg::NOT_INIT;
            }
        }
    };
    forget(&mut *st.regs, live[pc]);
    for f in st.callers.iter_mut() {
        forget(&mut *f.regs, live[f.callsite + 1]);
    }
}

/// One frame of a kept state. The slots of the stack below `lo` are not set, and the frame
/// does not keep them.
#[derive(Debug)]
struct KeptFrame {
    regs: Box<[Reg; MAX_BPF_REG]>,
    lo: usize,
    stack: Vec<StackSlot>,
    subprog: usize,
    /// The instruction of the call, `usize::MAX` for the frame that runs.
    callsite: usize,
}

impl KeptFrame {
    fn new(
        regs: &[Reg; MAX_BPF_REG],
        stack: &[StackSlot],
        subprog: usize,
        callsite: usize,
    ) -> Self {
        let lo = stack.iter().position(|s| *s != StackSlot::EMPTY).unwrap_or(stack.len());
        KeptFrame { regs: Box::new(*regs), lo, stack: stack[lo..].to_vec(), subprog, callsite }
    }

    fn bytes(&self) -> usize {
        core::mem::size_of::<Self>()
            + core::mem::size_of::<[Reg; MAX_BPF_REG]>()
            + self.stack.len() * core::mem::size_of::<StackSlot>()
    }
}

/// A state in the list of an instruction, `struct bpf_verifier_state_list` of Linux.
#[derive(Debug)]
struct Kept {
    /// The callers first, and the frame that runs last.
    frames: Vec<KeptFrame>,
    /// The state is on the path that `do_check` follows now, so its paths are not all
    /// explored, as `branches` of Linux that is not 0.
    on_path: bool,
    uid: u32,
    hit: u32,
    miss: u32,
}

/// The frames of a state, the callers first.
fn frames_of(
    st: &State,
) -> impl Iterator<Item = (&[Reg; MAX_BPF_REG], &[StackSlot], usize, usize)> {
    st.callers
        .iter()
        .map(|f| (&*f.regs, &f.stack[..], f.subprog, f.callsite))
        .chain(core::iter::once((&*st.regs, &st.stack[..], st.subprog, usize::MAX)))
}

impl Kept {
    fn new(st: &State, uid: u32) -> Self {
        let frames = frames_of(st).map(|(r, s, p, c)| KeptFrame::new(r, s, p, c)).collect();
        Kept { frames, on_path: true, uid, hit: 0, miss: 0 }
    }

    fn bytes(&self) -> usize {
        core::mem::size_of::<Self>() + self.frames.iter().map(KeptFrame::bytes).sum::<usize>()
    }

    /// Tells if the frames of `cur` are the frames of the kept state.
    fn same_frames(&self, cur: &State) -> bool {
        self.frames.len() == cur.callers.len() + 1
            && self.frames.iter().zip(frames_of(cur)).all(|(o, (_, _, subprog, callsite))| {
                o.subprog == subprog && o.callsite == callsite
            })
    }

    /// Tells if `cur` is the kept state, for the check of a loop that does not end.
    fn equal(&self, cur: &State) -> bool {
        self.same_frames(cur)
            && self.frames.iter().zip(frames_of(cur)).all(|(o, (regs, stack, _, _))| {
                *o.regs == *regs
                    && stack[..o.lo].iter().all(|s| *s == StackSlot::EMPTY)
                    && o.stack[..] == stack[o.lo..]
            })
    }

    /// Tells if `cur` is within the kept state, `states_equal` of Linux.
    fn safe(&self, cur: &State, allow_uninit_stack: bool) -> bool {
        let mut ids = IdMap(Vec::new());
        self.same_frames(cur)
            && self.frames.iter().zip(frames_of(cur)).all(|(o, (regs, stack, _, _))| {
                o.regs.iter().zip(regs.iter()).all(|(a, b)| regsafe(a, b, &mut ids))
                    && stacksafe(o, stack, allow_uninit_stack, &mut ids)
            })
    }
}

/// The IDs of the old state and of the new state that must go together, `struct bpf_idmap`
/// of Linux.
struct IdMap(Vec<(u32, u32)>);

impl IdMap {
    /// `check_ids` of Linux.
    fn check(&mut self, old: u32, cur: u32) -> bool {
        if (old == 0) != (cur == 0) {
            return false;
        }
        if old == 0 {
            return true;
        }
        for &(o, c) in &self.0 {
            if o == old {
                return c == cur;
            }
            if c == cur {
                return false;
            }
        }
        self.0.push((old, cur));
        true
    }
}

/// `range_within` of Linux.
fn range_within(old: &Reg, cur: &Reg) -> bool {
    old.umin <= cur.umin && cur.umax <= old.umax && old.smin <= cur.smin && cur.smax <= old.smax
}

/// Tells if the register `cur` is within the register `old`, `regsafe` of Linux.
fn regsafe(old: &Reg, cur: &Reg, ids: &mut IdMap) -> bool {
    if old.ty == RegType::NotInit {
        // The old paths did not read the register.
        return true;
    }
    if old.ty != cur.ty {
        return false;
    }
    match old.ty {
        RegType::Scalar => {
            range_within(old, cur) && old.var.contains(cur.var) && ids.check(old.id, cur.id)
        }
        RegType::PtrToMapValue | RegType::PtrToMapValueOrNull => {
            old.off == cur.off
                && old.map == cur.map
                && old.frameno == cur.frameno
                && range_within(old, cur)
                && old.var.contains(cur.var)
                && ids.check(old.id, cur.id)
        }
        _ => Reg { id: 0, ..*old } == Reg { id: 0, ..*cur } && ids.check(old.id, cur.id),
    }
}

/// Tells if the stack `cur` is within the stack of the frame `old`, `stacksafe` of Linux. A
/// byte that the old state did not set is safe, because a read of it gives an error. When the
/// loader can read bytes that are not set, `allow_uninit_stack` of Linux, such a read gives an
/// unknown scalar, as a read of `STACK_MISC`.
fn stacksafe(
    old: &KeptFrame,
    cur: &[StackSlot],
    allow_uninit_stack: bool,
    ids: &mut IdMap,
) -> bool {
    for (o, c) in old.stack.iter().zip(&cur[old.lo..]) {
        for (&old_type, &cur_type) in o.slot_type.iter().zip(&c.slot_type) {
            let ok = match old_type {
                STACK_INVALID => !allow_uninit_stack || cur_type != STACK_SPILL,
                STACK_MISC => {
                    cur_type == STACK_MISC || (allow_uninit_stack && cur_type == STACK_INVALID)
                }
                _ => cur_type == STACK_SPILL,
            };
            if !ok {
                return false;
            }
        }
        if o.slot_type[0] == STACK_SPILL && !regsafe(&o.spilled, &c.spilled, ids) {
            return false;
        }
    }
    true
}

/// What `StateLists::visit` found.
pub(super) enum Visit {
    /// A safe state has the new state within it, so the path stops.
    Prune,
    /// The new state is a state on the path, so the loop does not end.
    Loop,
    /// `do_check` goes on with the new state.
    Go,
}

/// The statistics of `print_verification_stats` of Linux.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Stats {
    pub max_states_per_insn: usize,
    pub total_states: usize,
    pub peak_states: usize,
}

/// The kept states of each instruction, `explored_states` of Linux.
pub(super) struct StateLists {
    kept: Vec<Vec<Kept>>,
    /// The states on the path that `do_check` follows now, as the instruction and the ID.
    path: Vec<(usize, u32)>,
    next_uid: u32,
    bytes: usize,
    states: usize,
    /// The counts of `do_check` when the lists last kept a state, `prev_jmps_processed` and
    /// `prev_insn_processed` of Linux.
    prev_jmps: u32,
    prev_insns: u32,
    pub stats: Stats,
}

impl StateLists {
    pub(super) fn new(n: usize) -> Self {
        StateLists {
            kept: (0..n).map(|_| Vec::new()).collect(),
            path: Vec::new(),
            next_uid: 0,
            bytes: 0,
            states: 0,
            prev_jmps: 0,
            prev_insns: 0,
            stats: Stats::default(),
        }
    }

    /// The length of the path, to give to `leave_path` when a branch that waits starts.
    pub(super) fn path_len(&self) -> usize {
        self.path.len()
    }

    /// A branch that waited starts at the path length `depth`. The paths of the states after it
    /// are all explored, as `update_branch_counts` of Linux.
    pub(super) fn leave_path(&mut self, depth: usize) {
        for (pc, uid) in self.path.drain(depth..) {
            if let Some(k) = self.kept[pc].iter_mut().find(|k| k.uid == uid) {
                k.on_path = false;
            }
        }
    }

    /// Compares the state `cur` at the instruction `pc` with the kept states, and keeps it,
    /// `is_state_visited` of Linux. `insns` and `jmps` are the counts of `do_check` of the
    /// instructions and of the jumps.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn visit(
        &mut self,
        pc: usize,
        cur: &mut State,
        live: &[u16],
        bpf_capable: bool,
        allow_uninit_stack: bool,
        insns: u32,
        jmps: u32,
    ) -> Visit {
        // Linux keeps a state only after 2 jumps and 8 instructions, because a program
        // usually has a prune point each 4 instructions.
        let mut add = jmps - self.prev_jmps >= 2 && insns - self.prev_insns >= 8;
        clean(cur, pc, live);
        let list = &mut self.kept[pc];
        let count = list.len();
        let mut i = 0;
        while i < list.len() {
            let k = &mut list[i];
            if k.on_path {
                if k.equal(cur) {
                    return Visit::Loop;
                }
                // The state is in a loop. Linux keeps a new state in a loop only after 20 jumps
                // or 100 instructions.
                if jmps - self.prev_jmps < 20 && insns - self.prev_insns < 100 {
                    add = false;
                }
            } else if k.safe(cur, allow_uninit_stack) {
                k.hit += 1;
                return Visit::Prune;
            }
            if add {
                k.miss += 1;
            }
            // A state that misses often is not useful.
            if k.miss > k.hit * 3 + 3 {
                let k = list.swap_remove(i);
                self.bytes -= k.bytes();
                self.states -= 1;
                continue;
            }
            i += 1;
        }
        self.stats.max_states_per_insn = self.stats.max_states_per_insn.max(count);
        if !add || (!bpf_capable && list.len() > BPF_COMPLEXITY_LIMIT_STATES) {
            return Visit::Go;
        }
        let k = Kept::new(cur, self.next_uid);
        let bytes = k.bytes();
        if self.bytes + bytes > MAX_KEPT_BYTES {
            return Visit::Go;
        }
        self.path.push((pc, k.uid));
        self.next_uid = self.next_uid.wrapping_add(1);
        list.push(k);
        self.bytes += bytes;
        self.states += 1;
        self.stats.total_states += 1;
        self.stats.peak_states = self.stats.peak_states.max(self.states);
        self.prev_jmps = jmps;
        self.prev_insns = insns;
        Visit::Go
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::insn::asm::*;
    use crate::tnum::Tnum;

    #[test]
    fn a_register_is_live_until_the_program_writes_it() {
        // 0: r0 = r1, 1: r2 = 1, 2: if r2 > r0 goto 4, 3: r0 = 0, 4: exit
        let insns =
            [mov64_reg(0, 1), mov64_imm(2, 1), jmp_reg(BPF_JGT, 2, 0, 1), mov64_imm(0, 0), exit()];
        let live = live_regs(&insns);
        assert_eq!(live[0], 1 << 1);
        assert_eq!(live[1], 1 << 0);
        assert_eq!(live[2], (1 << 0) | (1 << 2));
        assert_eq!(live[3], 0);
        assert_eq!(live[4], 1 << 0);
    }

    #[test]
    fn a_call_reads_the_arguments_and_clobbers_r0_to_r5() {
        // 0: r6 = r1, 1: call 7, 2: r0 = r6, 3: exit
        let insns = [mov64_reg(6, 1), call(7), mov64_reg(0, 6), exit()];
        let live = live_regs(&insns);
        assert_eq!(live[1], ARGS | (1 << 6));
        assert_eq!(live[0], ARGS);
    }

    #[test]
    fn a_scalar_within_the_old_scalar_is_safe() {
        let mut ids = IdMap(Vec::new());
        let wide = Reg::from_tnum(Tnum::range(0, 255));
        let narrow = Reg::from_tnum(Tnum::range(0, 15));
        assert!(regsafe(&wide, &narrow, &mut ids));
        assert!(!regsafe(&narrow, &wide, &mut ids));
        assert!(regsafe(&Reg::NOT_INIT, &wide, &mut ids));
        assert!(!regsafe(&wide, &Reg::NOT_INIT, &mut ids));
        assert!(!regsafe(&wide, &Reg::ptr(RegType::PtrToCtx), &mut ids));
    }

    #[test]
    fn the_ids_of_two_states_must_go_together() {
        let mut ids = IdMap(Vec::new());
        assert!(ids.check(1, 5));
        assert!(ids.check(1, 5));
        assert!(!ids.check(1, 6));
        assert!(!ids.check(2, 5));
        assert!(!ids.check(0, 5));
        assert!(ids.check(0, 0));
    }
}
