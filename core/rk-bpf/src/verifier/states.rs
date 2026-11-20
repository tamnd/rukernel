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
//! The verifier tracks the precision of the scalars, as `mark_chain_precision` of Linux. A
//! scalar of a kept state is precise when a path from the state used its bounds: as the offset
//! of a pointer, in a jump that the verifier knew the result of, as the size of the memory of a
//! helper, or as the return value. The backtracking follows the instructions of the path back
//! from the use, with the jump history of each state, and marks the scalars of the parent
//! states that gave the value. Only a precise old scalar must contain the new scalar. Without
//! `CAP_BPF` each scalar is precise, as in Linux.

use super::{
    Reg, RegType, SLOTS, STACK_INVALID, STACK_MISC, STACK_SPILL, StackSlot, State, successors,
};
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
/// each register, so that the instruction does not change the liveness. `args` gives the
/// arguments of a helper.
fn use_def(insns: &[BpfInsn], i: usize, args: &dyn Fn(i32) -> u16) -> (u16, u16) {
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
            // A helper reads only its arguments, as `get_call_summary` of Linux.
            BPF_CALL if insn.src_reg == 0 => (args(insn.imm), CALLER_SAVED),
            BPF_CALL => (ARGS, CALLER_SAVED),
            _ => (dst | x, 0),
        },
        _ => (ALL, 0),
    }
}

/// The registers that are live before each instruction, `compute_live_registers` of Linux: a
/// register is live when a path from the instruction can read it before it writes it. A call of
/// a function of the program goes on at the next instruction, and the function has its own
/// liveness. `check_cfg` checked the jumps. `args` gives the registers that the helper with
/// the ID reads.
pub(super) fn live_regs(insns: &[BpfInsn], args: &dyn Fn(i32) -> u16) -> Vec<u16> {
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
        (0..n).map(|i| if half[i] { (0, 0) } else { use_def(insns, i, args) }).collect();
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

/// A stack slot that an instruction spilled to or filled from, `INSN_F_STACK_ACCESS` of Linux:
/// the frame and the index of the slot.
pub(super) type SlotRef = (u8, u8);

/// An entry of the jump history of a state, `struct bpf_jmp_history_entry` of Linux. `do_check`
/// adds an entry when a path comes to an instruction from an instruction that is not the one
/// before it, and when an instruction spills a register to the stack or fills it back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Hist {
    pub idx: u32,
    /// The instruction before on the path, `u32::MAX` at the start of the program.
    pub prev: u32,
    pub slot: Option<SlotRef>,
}

/// The registers and the stack slots that need precision, `struct backtrack_state` of Linux.
/// Each frame has a mask of registers and a mask of stack slots.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Bt {
    frame: usize,
    regs: [u16; MAX_CALL_FRAMES],
    stack: [u64; MAX_CALL_FRAMES],
}

impl Bt {
    /// The registers `regs` of the frame `frame` need precision.
    pub(super) fn regs(frame: usize, regs: u16) -> Bt {
        let mut bt = Bt { frame, ..Bt::default() };
        bt.regs[frame] = regs;
        bt
    }

    fn is_empty(&self) -> bool {
        self.regs.iter().all(|&r| r == 0) && self.stack.iter().all(|&s| s == 0)
    }

    fn is_reg_set(&self, regno: u8) -> bool {
        self.regs[self.frame] & bit(regno) != 0
    }

    fn set_reg(&mut self, regno: u8) {
        self.regs[self.frame] |= bit(regno);
    }

    fn clear_reg(&mut self, regno: u8) {
        self.regs[self.frame] &= !bit(regno);
    }

    fn is_slot_set(&self, (fr, spi): SlotRef) -> bool {
        self.stack[fr as usize] & (1 << spi) != 0
    }

    fn set_slot(&mut self, (fr, spi): SlotRef) {
        self.stack[fr as usize] |= 1 << spi;
    }

    fn clear_slot(&mut self, (fr, spi): SlotRef) {
        self.stack[fr as usize] &= !(1 << spi);
    }
}

/// The backtracking cannot follow an instruction, `-ENOTSUPP` of Linux. Then the verifier marks
/// each scalar of the parent states precise, as `mark_all_scalars_precise` of Linux. Where
/// Linux finds a bug of the backtracking and gives `-EFAULT`, rukernel does the same as for
/// `-ENOTSUPP`, because it is always safe.
struct Unsupported;

/// Moves the need of precision from after the instruction `idx` to before it, `backtrack_insn`
/// of Linux. `subseq` is the instruction after `idx` on the path, and `hist` is the history
/// entry of `idx`.
fn backtrack_insn(
    insns: &[BpfInsn],
    idx: usize,
    subseq: Option<usize>,
    hist: Option<Hist>,
    bt: &mut Bt,
) -> Result<(), Unsupported> {
    let insn = insns[idx];
    // The second half of `BPF_LD_IMM64`.
    if insn.code == 0 {
        return Ok(());
    }
    let class = bpf_class(insn.code);
    let op = bpf_op(insn.code);
    let x = bpf_src(insn.code) == BPF_X;
    let (dreg, sreg) = (insn.dst_reg, insn.src_reg);
    let slot = hist.and_then(|h| h.slot);
    match class {
        BPF_ALU | BPF_ALU64 => {
            if !bt.is_reg_set(dreg) {
                return Ok(());
            }
            match op {
                // `dreg` needs precision before the instruction too.
                BPF_END | BPF_NEG => {}
                // `dreg = sreg` or `dreg = K`.
                BPF_MOV => {
                    bt.clear_reg(dreg);
                    if x {
                        bt.set_reg(sreg);
                    }
                }
                // `dreg op= sreg` needs both. `dreg op= K` needs only `dreg`.
                _ => {
                    if x {
                        bt.set_reg(sreg);
                    }
                }
            }
        }
        BPF_LDX => {
            if !bt.is_reg_set(dreg) {
                return Ok(());
            }
            bt.clear_reg(dreg);
            // A fill from the stack: the slot needs precision. A load of other memory gives a
            // value that the verifier does not know more about.
            if let Some(s) = slot {
                bt.set_slot(s);
            }
        }
        // Linux does not follow the value that an atomic instruction loads. rukernel gives up
        // when the instruction touches a register or a slot that needs precision.
        BPF_STX if bpf_mode(insn.code) == BPF_ATOMIC => {
            let load = if insn.imm == BPF_CMPXCHG {
                Some(0)
            } else if insn.imm & BPF_FETCH != 0 {
                Some(sreg)
            } else {
                None
            };
            if bt.is_reg_set(dreg)
                || load.is_some_and(|r| bt.is_reg_set(r))
                || slot.is_some_and(|s| bt.is_slot_set(s))
            {
                return Err(Unsupported);
            }
        }
        BPF_STX | BPF_ST => {
            // A scalar is not the address of a store.
            if bt.is_reg_set(dreg) {
                return Err(Unsupported);
            }
            let Some(s) = slot else {
                return Ok(());
            };
            if !bt.is_slot_set(s) {
                return Ok(());
            }
            // A spill: the source register needs precision before it. `BPF_ST` spills a
            // constant.
            bt.clear_slot(s);
            if class == BPF_STX {
                bt.set_reg(sreg);
            }
        }
        BPF_JMP | BPF_JMP32 => match op {
            BPF_CALL if sreg == BPF_PSEUDO_CALL => {
                // The backtracking leaves the function at its call. Only its arguments can
                // still need precision, and they go to the caller.
                let args = bt.regs[bt.frame];
                if args & !ARGS != 0 || bt.stack[bt.frame] != 0 || bt.frame == 0 {
                    return Err(Unsupported);
                }
                bt.regs[bt.frame] = 0;
                bt.frame -= 1;
                bt.regs[bt.frame] |= args;
            }
            BPF_CALL => {
                // A helper sets R0. R1 to R5 are not set after the call, so nothing can read
                // them.
                bt.clear_reg(0);
                if bt.regs[bt.frame] & ARGS != 0 {
                    return Err(Unsupported);
                }
            }
            BPF_EXIT => {
                // The backtracking goes into a function at its exit. R0 of the caller is R0 of
                // the function.
                if bt.regs[bt.frame] & ARGS != 0 || bt.frame + 1 >= MAX_CALL_FRAMES {
                    return Err(Unsupported);
                }
                let r0 = bt.is_reg_set(0);
                let call = subseq.is_some_and(|s| {
                    s >= 1
                        && bpf_class(insns[s - 1].code) == BPF_JMP
                        && bpf_op(insns[s - 1].code) == BPF_CALL
                        && insns[s - 1].src_reg == BPF_PSEUDO_CALL
                });
                bt.clear_reg(0);
                bt.frame += 1;
                if r0 && call {
                    bt.set_reg(0);
                }
            }
            // `dreg op sreg`: both need precision before the jump. `dreg op K` needs nothing
            // new.
            _ => {
                if x && (bt.is_reg_set(dreg) || bt.is_reg_set(sreg)) {
                    bt.set_reg(dreg);
                    bt.set_reg(sreg);
                }
            }
        },
        BPF_LD => {
            if !bt.is_reg_set(dreg) {
                return Ok(());
            }
            bt.clear_reg(dreg);
            if matches!(bpf_mode(insn.code), BPF_ABS | BPF_IND) {
                return Err(Unsupported);
            }
        }
        _ => {}
    }
    Ok(())
}

/// Walks back the instructions of one state, from `last` to its first instruction `first`, as
/// the inner loop of `__mark_chain_precision` of Linux. `hist` is the jump history of the
/// state. Gives true when nothing needs precision anymore.
fn backtrack_state(
    insns: &[BpfInsn],
    hist: &[Hist],
    first: usize,
    last: Option<usize>,
    subseq: &mut Option<usize>,
    skip_first: &mut bool,
    bt: &mut Bt,
) -> Result<bool, Unsupported> {
    // A state at the start of a function. Linux has this only for a global function.
    let Some(mut i) = last else {
        return Err(Unsupported);
    };
    let mut cnt = hist.len();
    loop {
        if *skip_first {
            *skip_first = false;
        } else {
            // `get_jmp_hist_entry`.
            let h = (cnt > 0 && hist[cnt - 1].idx as usize == i).then(|| hist[cnt - 1]);
            backtrack_insn(insns, i, *subseq, h, bt)?;
        }
        if bt.is_empty() {
            return Ok(true);
        }
        *subseq = Some(i);
        // `get_prev_insn_idx`.
        if i == first && (cnt == 0 || (cnt == 1 && hist[0].idx as usize == i)) {
            return Ok(false);
        }
        if cnt > 0 && hist[cnt - 1].idx as usize == i {
            let prev = hist[cnt - 1].prev;
            cnt -= 1;
            if prev == u32::MAX {
                return Err(Unsupported);
            }
            i = prev as usize;
        } else if i == 0 {
            return Err(Unsupported);
        } else {
            i -= 1;
        }
        if i >= insns.len() {
            return Err(Unsupported);
        }
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
    /// The scalar registers that are precise, the `precise` flags of Linux.
    reg_precise: u16,
    /// The spilled scalars that are precise, a bit for each slot of the stack.
    stack_precise: u64,
}

impl KeptFrame {
    fn new(
        regs: &[Reg; MAX_BPF_REG],
        stack: &[StackSlot],
        subprog: usize,
        callsite: usize,
    ) -> Self {
        let lo = stack.iter().position(|s| *s != StackSlot::EMPTY).unwrap_or(stack.len());
        KeptFrame {
            regs: Box::new(*regs),
            lo,
            stack: stack[lo..].to_vec(),
            subprog,
            callsite,
            reg_precise: 0,
            stack_precise: 0,
        }
    }

    fn bytes(&self) -> usize {
        core::mem::size_of::<Self>()
            + core::mem::size_of::<[Reg; MAX_BPF_REG]>()
            + self.stack.len() * core::mem::size_of::<StackSlot>()
    }

    /// Tells if the slot `spi` has a spilled scalar.
    fn spilled_scalar(&self, spi: usize) -> bool {
        spi >= self.lo && {
            let s = &self.stack[spi - self.lo];
            s.is_spill() && s.spilled.ty == RegType::Scalar
        }
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
    /// The list of the instruction does not have the state anymore. The state stays while it
    /// is on the path, because the backtracking reads it.
    evicted: bool,
    hit: u32,
    miss: u32,
    /// The first instruction of the path from the parent state, `first_insn_idx` of Linux.
    first_insn: usize,
    /// The instruction before this state, `last_insn_idx` of Linux.
    last_insn: Option<usize>,
    /// The jump history from the parent state, `jmp_history` of Linux.
    hist: Vec<Hist>,
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
    /// The state of a free ID of the slab.
    const EMPTY: Kept = Kept {
        frames: Vec::new(),
        on_path: false,
        evicted: false,
        hit: 0,
        miss: 0,
        first_insn: 0,
        last_insn: None,
        hist: Vec::new(),
    };

    fn new(st: &State) -> Self {
        let frames = frames_of(st).map(|(r, s, p, c)| KeptFrame::new(r, s, p, c)).collect();
        Kept {
            frames,
            on_path: true,
            evicted: false,
            hit: 0,
            miss: 0,
            first_insn: 0,
            last_insn: None,
            hist: Vec::new(),
        }
    }

    fn bytes(&self) -> usize {
        core::mem::size_of::<Self>()
            + self.frames.iter().map(KeptFrame::bytes).sum::<usize>()
            + self.hist.len() * core::mem::size_of::<Hist>()
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

    /// Tells if `cur` is within the kept state, `states_equal` of Linux. Without `CAP_BPF` each
    /// scalar is precise.
    fn safe(&self, cur: &State, allow_uninit_stack: bool, bpf_capable: bool) -> bool {
        let mut ids = IdMap(Vec::new());
        self.same_frames(cur)
            && self.frames.iter().zip(frames_of(cur)).all(|(o, (regs, stack, _, _))| {
                o.regs.iter().zip(regs.iter()).enumerate().all(|(r, (a, b))| {
                    regsafe(a, b, !bpf_capable || o.reg_precise & (1 << r) != 0, &mut ids)
                }) && stacksafe(o, stack, allow_uninit_stack, bpf_capable, &mut ids)
            })
    }

    /// Marks the registers and the slots of `bt` precise, as the loop over the frames of the
    /// parent state in `__mark_chain_precision` of Linux. A register or a slot that is precise
    /// already has precise parents, so the backtracking stops for it.
    fn mark_precise(&mut self, bt: &mut Bt) -> Result<(), Unsupported> {
        if self.frames.len() != bt.frame + 1 {
            return Err(Unsupported);
        }
        for (fr, f) in self.frames.iter_mut().enumerate() {
            for r in 0..MAX_BPF_REG {
                let b = 1u16 << r;
                if bt.regs[fr] & b == 0 {
                    continue;
                }
                if f.regs[r].ty != RegType::Scalar || f.reg_precise & b != 0 {
                    bt.regs[fr] &= !b;
                } else {
                    f.reg_precise |= b;
                }
            }
            for spi in 0..SLOTS {
                let b = 1u64 << spi;
                if bt.stack[fr] & b == 0 {
                    continue;
                }
                if !f.spilled_scalar(spi) || f.stack_precise & b != 0 {
                    bt.stack[fr] &= !b;
                } else {
                    f.stack_precise |= b;
                }
            }
        }
        Ok(())
    }

    /// Marks each scalar precise, as `mark_all_scalars_precise` of Linux.
    fn mark_all_precise(&mut self) {
        for f in &mut self.frames {
            for (r, reg) in f.regs.iter().enumerate() {
                if reg.ty == RegType::Scalar {
                    f.reg_precise |= 1 << r;
                }
            }
            for spi in f.lo..SLOTS {
                if f.spilled_scalar(spi) {
                    f.stack_precise |= 1 << spi;
                }
            }
        }
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

/// Tells if the register `cur` is within the register `old`, `regsafe` of Linux. When the old
/// scalar is not `precise`, no path from the old state used its bounds, so each scalar is safe.
fn regsafe(old: &Reg, cur: &Reg, precise: bool, ids: &mut IdMap) -> bool {
    if old.ty == RegType::NotInit {
        // The old paths did not read the register.
        return true;
    }
    if old.ty != cur.ty {
        return false;
    }
    match old.ty {
        RegType::Scalar => {
            !precise
                || (range_within(old, cur)
                    && old.var.contains(cur.var)
                    && ids.check(old.id, cur.id))
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
    bpf_capable: bool,
    ids: &mut IdMap,
) -> bool {
    for (i, (o, c)) in old.stack.iter().zip(&cur[old.lo..]).enumerate() {
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
        let precise = !bpf_capable || old.stack_precise & (1 << (old.lo + i)) != 0;
        if o.slot_type[0] == STACK_SPILL && !regsafe(&o.spilled, &c.spilled, precise, ids) {
            return false;
        }
    }
    true
}

/// What `StateLists::visit` found.
pub(super) enum Visit {
    /// The safe state with this ID has the new state within it, so the path stops.
    Prune(usize),
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
    /// The kept states by their ID. A free ID has a state without frames.
    slab: Vec<Kept>,
    free: Vec<usize>,
    /// The IDs of the kept states of each instruction.
    kept: Vec<Vec<usize>>,
    /// The IDs of the states on the path that `do_check` follows now, the oldest first. These
    /// are the parent states of the current state, the `parent` chain of Linux.
    path: Vec<usize>,
    bytes: usize,
    states: usize,
    /// The counts of `do_check` when the lists last kept a state, `prev_jmps_processed` and
    /// `prev_insn_processed` of Linux.
    prev_jmps: u32,
    prev_insns: u32,
    pub stats: Stats,
    /// The memory for the kept states was full once. Then each scalar of the path is precise,
    /// and the verifier does not track the precision anymore.
    full: bool,
}

impl StateLists {
    pub(super) fn new(n: usize) -> Self {
        StateLists {
            slab: Vec::new(),
            free: Vec::new(),
            kept: (0..n).map(|_| Vec::new()).collect(),
            path: Vec::new(),
            bytes: 0,
            states: 0,
            prev_jmps: 0,
            prev_insns: 0,
            stats: Stats::default(),
            full: false,
        }
    }

    fn get(&self, id: usize) -> &Kept {
        &self.slab[id]
    }

    fn get_mut(&mut self, id: usize) -> &mut Kept {
        &mut self.slab[id]
    }

    fn alloc(&mut self, k: Kept) -> usize {
        if let Some(id) = self.free.pop() {
            self.slab[id] = k;
            id
        } else {
            self.slab.push(k);
            self.slab.len() - 1
        }
    }

    fn release(&mut self, id: usize) {
        // A kept state has at least one frame.
        if self.slab[id].frames.is_empty() {
            return;
        }
        let k = core::mem::replace(&mut self.slab[id], Kept::EMPTY);
        self.bytes -= k.bytes();
        self.free.push(id);
    }

    /// The length of the path, to give to `leave_path` when a branch that waits starts.
    pub(super) fn path_len(&self) -> usize {
        self.path.len()
    }

    /// A branch that waited starts at the path length `depth`. The paths of the states after it
    /// are all explored, as `update_branch_counts` of Linux.
    pub(super) fn leave_path(&mut self, depth: usize) {
        while self.path.len() > depth {
            let Some(id) = self.path.pop() else { break };
            let k = self.get_mut(id);
            k.on_path = false;
            if k.evicted {
                self.release(id);
            }
        }
    }

    /// Compares the state `cur` at the instruction `pc` with the kept states, and keeps it,
    /// `is_state_visited` of Linux. `prev` is the instruction before `pc` on the path. `insns`
    /// and `jmps` are the counts of `do_check` of the instructions and of the jumps.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn visit(
        &mut self,
        pc: usize,
        prev: Option<usize>,
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
        let count = self.kept[pc].len();
        // Linux puts a new state at the head of the list, so it compares the newest state
        // first. The list here has the newest state at the end.
        let mut i = count;
        while i > 0 {
            i -= 1;
            let id = self.kept[pc][i];
            let k = &mut self.slab[id];
            if k.on_path {
                if k.equal(cur) {
                    return Visit::Loop;
                }
                // The state is in a loop. Linux keeps a new state in a loop only after 20 jumps
                // or 100 instructions.
                if jmps - self.prev_jmps < 20 && insns - self.prev_insns < 100 {
                    add = false;
                }
            } else if k.safe(cur, allow_uninit_stack, bpf_capable) {
                k.hit += 1;
                return Visit::Prune(id);
            }
            if add {
                k.miss += 1;
            }
            // A state that misses often is not useful.
            if k.miss > k.hit * 3 + 3 {
                k.evicted = true;
                let on_path = k.on_path;
                self.kept[pc].remove(i);
                self.states -= 1;
                if !on_path {
                    self.release(id);
                }
            }
        }
        self.stats.max_states_per_insn = self.stats.max_states_per_insn.max(count);
        if !add || (!bpf_capable && self.kept[pc].len() > BPF_COMPLEXITY_LIMIT_STATES) {
            return Visit::Go;
        }
        // The new state gets the history of the path from its parent, and the current state
        // starts a new history at `pc`.
        let mut k = Kept::new(cur);
        k.first_insn = cur.first_insn;
        k.last_insn = prev;
        k.hist = core::mem::take(&mut cur.hist);
        let bytes = k.bytes();
        if self.bytes + bytes > MAX_KEPT_BYTES {
            // Without new kept states, the backtracking would walk back over the full path for
            // each mark, and the history would have no limit. All the scalars of the path
            // become precise, which is always safe, and the precision tracking stops.
            if bpf_capable && !self.full {
                self.full = true;
                self.mark_all_scalars_precise();
            }
            return Visit::Go;
        }
        if self.full {
            k.mark_all_precise();
        }
        cur.first_insn = pc;
        let id = self.alloc(k);
        self.path.push(id);
        self.kept[pc].push(id);
        self.bytes += bytes;
        self.states += 1;
        self.stats.total_states += 1;
        self.stats.peak_states = self.stats.peak_states.max(self.states);
        self.prev_jmps = jmps;
        self.prev_insns = insns;
        Visit::Go
    }

    /// Marks the scalars of `bt` precise in the parent states of the current state,
    /// `__mark_chain_precision` of Linux. The current state is at the instruction `idx`, with
    /// the jump history `hist` from its first instruction `first`. As in Linux, the current
    /// state does not get the marks, and the backtracking starts before `idx`.
    pub(super) fn mark_chain_precision(
        &mut self,
        insns: &[BpfInsn],
        hist: &[Hist],
        first: usize,
        idx: usize,
        mut bt: Bt,
    ) {
        if self.full || bt.is_empty() {
            return;
        }
        let mut level = self.path.len();
        let (mut first, mut last) = (first, Some(idx));
        let mut subseq = None;
        let mut skip_first = true;
        loop {
            let h = if level == self.path.len() { hist } else { &self.get(self.path[level]).hist };
            match backtrack_state(insns, h, first, last, &mut subseq, &mut skip_first, &mut bt) {
                Ok(true) => return,
                Ok(false) => {}
                Err(Unsupported) => return self.mark_all_scalars_precise(),
            }
            if level == 0 {
                break;
            }
            level -= 1;
            let id = self.path[level];
            let k = self.get_mut(id);
            if k.mark_precise(&mut bt).is_err() {
                return self.mark_all_scalars_precise();
            }
            if bt.is_empty() {
                return;
            }
            subseq = Some(first);
            first = k.first_insn;
            last = k.last_insn;
        }
        // A register or a slot that still needs precision came from a way that the
        // backtracking does not know.
        self.mark_all_scalars_precise();
    }

    /// Marks each scalar of the parent states precise, `mark_all_scalars_precise` of Linux.
    fn mark_all_scalars_precise(&mut self) {
        for i in 0..self.path.len() {
            let id = self.path[i];
            self.get_mut(id).mark_all_precise();
        }
    }

    /// The current state is within the safe state `id`, so the precise scalars of the safe
    /// state must be precise in the parents of the current state too, `propagate_precision` of
    /// Linux.
    pub(super) fn propagate_precision(
        &mut self,
        insns: &[BpfInsn],
        id: usize,
        cur: &State,
        idx: usize,
    ) {
        let k = self.get(id);
        let mut bt = Bt { frame: cur.callers.len(), ..Bt::default() };
        for (fr, f) in k.frames.iter().enumerate() {
            bt.regs[fr] = f.reg_precise;
            bt.stack[fr] = f.stack_precise;
        }
        self.mark_chain_precision(insns, &cur.hist, cur.first_insn, idx, bt);
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
        let live = live_regs(&insns, &|_| ARGS);
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
        let live = live_regs(&insns, &|_| ARGS);
        assert_eq!(live[1], ARGS | (1 << 6));
        assert_eq!(live[0], ARGS);
        // A helper with two arguments reads only R1 and R2.
        let live = live_regs(&insns, &|_| 0b110);
        assert_eq!(live[1], 0b110 | (1 << 6));
        assert_eq!(live[0], 0b110);
    }

    #[test]
    fn a_scalar_within_the_old_scalar_is_safe() {
        let mut ids = IdMap(Vec::new());
        let wide = Reg::from_tnum(Tnum::range(0, 255));
        let narrow = Reg::from_tnum(Tnum::range(0, 15));
        assert!(regsafe(&wide, &narrow, true, &mut ids));
        assert!(!regsafe(&narrow, &wide, true, &mut ids));
        assert!(regsafe(&Reg::NOT_INIT, &wide, true, &mut ids));
        assert!(!regsafe(&wide, &Reg::NOT_INIT, true, &mut ids));
        assert!(!regsafe(&wide, &Reg::ptr(RegType::PtrToCtx), true, &mut ids));
    }

    #[test]
    fn a_scalar_that_is_not_precise_is_safe_with_each_scalar() {
        let mut ids = IdMap(Vec::new());
        let wide = Reg::from_tnum(Tnum::range(0, 255));
        let narrow = Reg::from_tnum(Tnum::range(0, 15));
        assert!(regsafe(&narrow, &wide, false, &mut ids));
        assert!(!regsafe(&narrow, &Reg::ptr(RegType::PtrToCtx), false, &mut ids));
    }

    #[test]
    fn backtracking_follows_the_registers_and_the_stack() {
        // 0: r1 = 4, 1: r2 = r1, 2: r2 += r3, 3: *(u64 *)(r10 - 8) = r2, 4: r0 = *(u64 *)(r10 - 8)
        let insns = [
            mov64_imm(1, 4),
            mov64_reg(2, 1),
            alu64_reg(BPF_ADD, 2, 3),
            stx_mem(BPF_DW, BPF_REG_FP, 2, -8),
            ldx_mem(BPF_DW, 0, BPF_REG_FP, -8),
        ];
        let slot = Some((0, 63));
        let mut bt = Bt::regs(0, 1);
        let fill = Hist { idx: 4, prev: 3, slot };
        assert!(backtrack_insn(&insns, 4, None, Some(fill), &mut bt).is_ok());
        assert_eq!((bt.regs[0], bt.stack[0]), (0, 1 << 63));
        let spill = Hist { idx: 3, prev: 2, slot };
        assert!(backtrack_insn(&insns, 3, Some(4), Some(spill), &mut bt).is_ok());
        assert_eq!((bt.regs[0], bt.stack[0]), (1 << 2, 0));
        assert!(backtrack_insn(&insns, 2, Some(3), None, &mut bt).is_ok());
        assert_eq!(bt.regs[0], (1 << 2) | (1 << 3));
        assert!(backtrack_insn(&insns, 1, Some(2), None, &mut bt).is_ok());
        assert_eq!(bt.regs[0], (1 << 1) | (1 << 3));
        assert!(backtrack_insn(&insns, 0, Some(1), None, &mut bt).is_ok());
        assert_eq!(bt.regs[0], 1 << 3);
        // A scalar that is the address of a store is not followed.
        let mut bt = Bt::regs(0, 1 << 10);
        assert!(backtrack_insn(&insns, 3, Some(4), Some(spill), &mut bt).is_err());
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
