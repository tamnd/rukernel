//! The `rt_sigframe` of the arm64 ABI, as arch/arm64/kernel/signal.c of Linux writes it. The
//! frame holds the `siginfo` and the `ucontext`. The `sigcontext` in the `ucontext` holds the
//! registers, and its reserved area holds a list of records. The kernel writes the record
//! `fpsimd_context` with the FP and SIMD state, and the end record. A frame record for the
//! unwinder is above the frame, with x29 and x30 of the code that the signal stopped.

use super::{get, put, set_altstack};
use crate::cx::{Cx, SysResult};
use alloc::vec;
use rk_abi::Errno;
use rk_abi::native::signal::{SA_ONSTACK, SA_RESTORER, SIGSEGV};
use rk_frame::user::{FpuState, UserContext};
use rk_mm::VmaKind;
use rk_proc::Thread;
use rk_proc::signal::{
    AltStack, SI_KERNEL, SIGINFO_SIZE, SS_AUTODISARM, SigAction, SigInfo, SigSet,
};

/// The offsets in `struct ucontext`: the flags, the link, the stack, the mask and the
/// `sigcontext`, which has an alignment of 16.
const UC_STACK: usize = 16;
const UC_SIGMASK: usize = 40;
const UC_MCONTEXT: usize = 176;
/// The offsets in `struct sigcontext`: the fault address, x0 to x30, sp, pc, pstate and the
/// reserved area of 4096 bytes.
const SC_REGS: usize = 8;
const SC_SP: usize = 256;
const SC_PC: usize = 264;
const SC_PSTATE: usize = 272;
const SC_RESERVED: usize = 288;
const RESERVED_SIZE: usize = 4096;
/// The size of `struct ucontext`.
const UCONTEXT_SIZE: usize = UC_MCONTEXT + SC_RESERVED + RESERVED_SIZE;
/// The size of `struct rt_sigframe`: the `siginfo` and the `ucontext`.
const FRAME_SIZE: u64 = (SIGINFO_SIZE + UCONTEXT_SIZE) as u64;
/// The size of `struct frame_record`: x29 and x30.
const RECORD_SIZE: u64 = 16;

/// The magic number and the size of the record `fpsimd_context`: the header, FPSR, FPCR and the
/// registers v0 to v31.
const FPSIMD_MAGIC: u32 = 0x4650_8001;
const FPSIMD_SIZE: usize = 16 + 32 * 16;
/// The offsets of FPSR and FPCR in `FpuState`, after v0 to v31.
const FPU_FPSR: usize = 512;

/// The PSTATE bits that `rt_sigreturn` takes from the frame: the flags NZCV. The other bits of
/// EL0 are for the kernel, and `valid_user_regs` of Linux clears them too.
const PSTATE_USER: u64 = 0xf000_0000;

/// Writes the record `fpsimd_context` and the end record in the reserved area `b`.
fn put_fpsimd(b: &mut [u8], fpu: &FpuState) {
    let fp = fpu.as_bytes();
    b[0..4].copy_from_slice(&FPSIMD_MAGIC.to_ne_bytes());
    b[4..8].copy_from_slice(&(FPSIMD_SIZE as u32).to_ne_bytes());
    b[8..16].copy_from_slice(&fp[FPU_FPSR..FPU_FPSR + 8]);
    b[16..FPSIMD_SIZE].copy_from_slice(&fp[..FPU_FPSR]);
    // The end record is 8 bytes of 0 after the record. The area is 0 already.
}

/// Finds the record `fpsimd_context` in the reserved area `b` and reads the state from it, as
/// `parse_user_sigframe` of Linux does. Gives `None` if the list is not valid or has no such
/// record.
fn get_fpsimd(b: &[u8]) -> Option<FpuState> {
    let mut off = 0;
    while off + 8 <= b.len() {
        let magic = u32::from_ne_bytes(b[off..off + 4].try_into().ok()?);
        let size = u32::from_ne_bytes(b[off + 4..off + 8].try_into().ok()?) as usize;
        if magic == 0 {
            return None;
        }
        if size < 8 || !size.is_multiple_of(16) || off + size > b.len() {
            return None;
        }
        if magic == FPSIMD_MAGIC {
            if size != FPSIMD_SIZE {
                return None;
            }
            let rec = &b[off..off + size];
            let mut a = [0u8; FpuState::SIZE];
            a[..FPU_FPSR].copy_from_slice(&rec[16..FPSIMD_SIZE]);
            a[FPU_FPSR..FPU_FPSR + 8].copy_from_slice(&rec[8..16]);
            return Some(FpuState::from_bytes(&a));
        }
        off += size;
    }
    None
}

/// Writes the frame of `info` on the user stack and sets the registers for the handler, as
/// `setup_rt_frame` of Linux does. The frame holds the registers of `regs`, the FP and SIMD state
/// and `mask`, the mask that `rt_sigreturn` puts back.
pub(super) fn setup_frame(
    thread: &Thread,
    regs: &mut UserContext,
    info: &SigInfo,
    action: &SigAction,
    mask: SigSet,
) -> Result<(), Errno> {
    let vm = thread.process().vm().ok_or(Errno::EFAULT)?;
    // Without `SA_RESTORER` the handler returns to `__kernel_rt_sigreturn` of the vDSO, as on
    // Linux.
    let restorer = if action.flags & u64::from(SA_RESTORER) != 0 {
        action.restorer
    } else {
        let vdso = vm.find_kind(VmaKind::Vdso).ok_or(Errno::EFAULT)?;
        (vdso + rk_frame::vdso::SIGRETURN) as u64
    };
    let user_sp = regs.sp();
    let alt = thread.altstack();
    let mut sp = user_sp;
    if action.flags & u64::from(SA_ONSTACK) != 0 && alt.size != 0 && !alt.contains(user_sp) {
        sp = alt.sp + alt.size;
    }
    let record = sp.wrapping_sub(RECORD_SIZE) & !15;
    let frame = record.wrapping_sub(FRAME_SIZE) & !15;

    let r = *regs.regs();
    let mut b = vec![0u8; FRAME_SIZE as usize];
    b[..SIGINFO_SIZE].copy_from_slice(&info.to_bytes());
    let uc = &mut b[SIGINFO_SIZE..];
    put(uc, UC_STACK, alt.sp);
    uc[UC_STACK + 8..UC_STACK + 12].copy_from_slice(&alt.flags_at(user_sp).to_ne_bytes());
    put(uc, UC_STACK + 16, alt.size);
    put(uc, UC_SIGMASK, mask.0);
    let sc = &mut uc[UC_MCONTEXT..];
    for (i, x) in r.x.iter().enumerate() {
        put(sc, SC_REGS + i * 8, *x);
    }
    put(sc, SC_SP, r.sp);
    put(sc, SC_PC, r.pc);
    put(sc, SC_PSTATE, r.pstate);
    put_fpsimd(&mut sc[SC_RESERVED..], regs.fpu());
    vm.write(frame as usize, &b)?;
    let mut rec = [0u8; RECORD_SIZE as usize];
    put(&mut rec, 0, r.x[29]);
    put(&mut rec, 8, r.x[30]);
    vm.write(record as usize, &rec)?;

    if alt.flags & SS_AUTODISARM != 0 {
        thread.set_altstack(AltStack::default());
    }
    let r = regs.regs_mut();
    r.x[0] = u64::from(info.signo);
    r.x[1] = frame;
    r.x[2] = frame + SIGINFO_SIZE as u64;
    r.x[29] = record;
    r.x[30] = restorer;
    r.sp = frame;
    r.pc = action.handler;
    // The handler starts with a clean FP and SIMD state, as `fpsimd_signal_preserve_current_state`
    // and the handler entry of Linux give it.
    regs.set_fpu(FpuState::default());
    Ok(())
}

/// Loads the registers, the mask and the alternate stack from the frame of the handler that
/// returns, as `sys_rt_sigreturn` of Linux does. The stack pointer points to the frame. A frame
/// that is not valid gives `SIGSEGV`.
pub(crate) fn rt_sigreturn(cx: &mut Cx<'_>) -> SysResult {
    let frame = cx.regs.sp();
    let b = if frame.is_multiple_of(16) {
        cx.read_bytes(frame + SIGINFO_SIZE as u64, UCONTEXT_SIZE).ok()
    } else {
        None
    };
    let Some(b) = b else {
        cx.thread.force_signal(SigInfo::new(SIGSEGV, SI_KERNEL, 0));
        return Ok(0);
    };
    let sc = &b[UC_MCONTEXT..];
    let Some(fpu) = get_fpsimd(&sc[SC_RESERVED..]) else {
        cx.thread.force_signal(SigInfo::new(SIGSEGV, SI_KERNEL, 0));
        return Ok(0);
    };
    let mut regs = *cx.regs;
    let r = regs.regs_mut();
    for (i, x) in r.x.iter_mut().enumerate() {
        *x = get(sc, SC_REGS + i * 8);
    }
    r.sp = get(sc, SC_SP);
    r.pc = get(sc, SC_PC);
    r.pstate = get(sc, SC_PSTATE) & PSTATE_USER;
    regs.set_fpu(fpu);
    *cx.regs = regs;
    cx.thread.set_blocked(SigSet(get(&b, UC_SIGMASK)));
    // The call that the handler interrupted does not continue, as in Linux.
    cx.thread.set_restart(None);
    let flags =
        u32::from_ne_bytes([b[UC_STACK + 8], b[UC_STACK + 9], b[UC_STACK + 10], b[UC_STACK + 11]]);
    let stack = AltStack { sp: get(&b, UC_STACK), size: get(&b, UC_STACK + 16), flags };
    let _ = set_altstack(cx.thread, stack, cx.regs.sp());
    Ok(cx.regs.syscall_return())
}
