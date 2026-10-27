//! The `rt_sigframe` of the x86-64 ABI, as arch/x86/kernel/signal.c and signal_64.c of Linux
//! write it. The frame holds the return address, the `ucontext` with the `sigcontext`, and the
//! `siginfo`. The FPU state is in the FXSAVE format above the frame.

use super::{get, put, set_altstack};
use crate::cx::{Cx, SysResult};
use alloc::vec;
use rk_abi::Errno;
use rk_abi::native::signal::{SA_ONSTACK, SA_RESTORER, SIGSEGV};
use rk_frame::user::{FpuState, UserContext};
use rk_proc::Thread;
use rk_proc::signal::{
    AltStack, SI_KERNEL, SIGINFO_SIZE, SS_AUTODISARM, SigAction, SigInfo, SigSet,
};

/// The bytes below the stack pointer that a leaf function can use. The frame goes below them.
const RED_ZONE: u64 = 128;
/// The size of `struct ucontext`: the flags, the link, the stack, the `sigcontext` and the mask.
const UCONTEXT_SIZE: usize = 304;
/// The size of `struct rt_sigframe`: the return address, the `ucontext` and the `siginfo`.
const FRAME_SIZE: u64 = 8 + UCONTEXT_SIZE as u64 + SIGINFO_SIZE as u64;
/// The offsets in `struct ucontext`.
const UC_STACK: usize = 16;
const UC_MCONTEXT: usize = 40;
const UC_SIGMASK: usize = 296;
/// The `uc_flags` of a 64 bit frame: the frame holds SS, and `rt_sigreturn` loads it as it is.
const UC_FLAGS: u64 = 0x2 | 0x4;
/// The user code and stack selectors, as the GDT of rk-frame has them.
const USER_CS: u16 = 0x33;
const USER_SS: u16 = 0x2b;

/// The flags that `rt_sigreturn` takes from the frame: AC, OF, DF, TF, SF, ZF, AF, PF, CF and RF.
/// Linux names this set `FIX_EFLAGS`.
const FIX_EFLAGS: u64 = 0x0005_0dd5;
/// The flags that the kernel clears for a handler: DF, TF and RF.
const HANDLER_CLEAR: u64 = (1 << 10) | (1 << 8) | (1 << 16);

/// Writes the `sigcontext` of `regs` in `b`. The order is the order of `struct sigcontext_64`:
/// r8 to r15, rdi, rsi, rbp, rbx, rdx, rax, rcx, rsp, rip, eflags, the selectors, err, trapno,
/// oldmask, cr2 and the address of the FPU state.
fn put_sigcontext(b: &mut [u8], regs: &UserContext, mask: SigSet, fpstate: u64) {
    let r = regs.regs();
    let words = [
        r.r8, r.r9, r.r10, r.r11, r.r12, r.r13, r.r14, r.r15, r.rdi, r.rsi, r.rbp, r.rbx, r.rdx,
        r.rax, r.rcx, r.rsp, r.rip, r.rflags,
    ];
    for (i, w) in words.iter().enumerate() {
        put(b, i * 8, *w);
    }
    b[144..146].copy_from_slice(&USER_CS.to_ne_bytes());
    b[150..152].copy_from_slice(&USER_SS.to_ne_bytes());
    put(b, 168, mask.0);
    put(b, 184, fpstate);
}

/// Reads the registers of a `sigcontext` into `regs`. Gives the address of the FPU state.
fn get_sigcontext(b: &[u8], regs: &mut UserContext) -> u64 {
    let r = regs.regs_mut();
    let dst = [
        &mut r.r8, &mut r.r9, &mut r.r10, &mut r.r11, &mut r.r12, &mut r.r13, &mut r.r14,
        &mut r.r15, &mut r.rdi, &mut r.rsi, &mut r.rbp, &mut r.rbx, &mut r.rdx, &mut r.rax,
        &mut r.rcx, &mut r.rsp, &mut r.rip,
    ];
    for (i, d) in dst.into_iter().enumerate() {
        *d = get(b, i * 8);
    }
    r.rflags = (r.rflags & !FIX_EFLAGS) | (get(b, 136) & FIX_EFLAGS);
    get(b, 184)
}

/// Writes the frame of `info` on the user stack and sets the registers for the handler. The
/// frame holds the registers of `regs`, the FPU state and `mask`, the mask that `rt_sigreturn`
/// puts back.
pub(super) fn setup_frame(
    thread: &Thread,
    regs: &mut UserContext,
    info: &SigInfo,
    action: &SigAction,
    mask: SigSet,
) -> Result<(), Errno> {
    if action.flags & u64::from(SA_RESTORER) == 0 {
        return Err(Errno::EFAULT);
    }
    let vm = thread.process().vm().ok_or(Errno::EFAULT)?;
    let user_sp = regs.regs().rsp;
    let alt = thread.altstack();
    let mut sp = user_sp.wrapping_sub(RED_ZONE);
    if action.flags & u64::from(SA_ONSTACK) != 0 && alt.size != 0 && !alt.contains(user_sp) {
        sp = alt.sp + alt.size;
    }
    let fpstate = sp.wrapping_sub(FpuState::SIZE as u64) & !63;
    let frame = (fpstate.wrapping_sub(FRAME_SIZE) & !15).wrapping_sub(8);

    let mut fp = *regs.fpu().as_bytes();
    // The bytes after 464 are free for software. With no XSAVE data, they stay 0.
    fp[464..].fill(0);
    vm.write(fpstate as usize, &fp)?;

    let mut b = vec![0u8; FRAME_SIZE as usize];
    put(&mut b, 0, action.restorer);
    let uc = &mut b[8..8 + UCONTEXT_SIZE];
    put(uc, 0, UC_FLAGS);
    put(uc, UC_STACK, alt.sp);
    uc[UC_STACK + 8..UC_STACK + 12].copy_from_slice(&alt.flags_at(user_sp).to_ne_bytes());
    put(uc, UC_STACK + 16, alt.size);
    put_sigcontext(&mut uc[UC_MCONTEXT..UC_SIGMASK], regs, mask, fpstate);
    put(uc, UC_SIGMASK, mask.0);
    b[8 + UCONTEXT_SIZE..].copy_from_slice(&info.to_bytes());
    vm.write(frame as usize, &b)?;

    if alt.flags & SS_AUTODISARM != 0 {
        thread.set_altstack(AltStack::default());
    }
    let r = regs.regs_mut();
    r.rdi = u64::from(info.signo);
    r.rsi = frame + 8 + UCONTEXT_SIZE as u64;
    r.rdx = frame + 8;
    r.rax = 0;
    r.rsp = frame;
    r.rip = action.handler;
    r.rflags &= !HANDLER_CLEAR;
    // The handler starts with a clean FPU, as `fpu__clear_user_states` of Linux gives it.
    regs.set_fpu(FpuState::default());
    Ok(())
}

/// Loads the registers, the mask and the alternate stack from the frame of the handler that
/// returns, as `sys_rt_sigreturn` of Linux does.
pub(crate) fn rt_sigreturn(cx: &mut Cx<'_>) -> SysResult {
    let uc = cx.regs.regs().rsp;
    let Ok(b) = cx.read_bytes(uc, UCONTEXT_SIZE) else {
        cx.thread.force_signal(SigInfo::new(SIGSEGV, SI_KERNEL, 0));
        return Ok(0);
    };
    let mut regs = *cx.regs;
    let fpstate = get_sigcontext(&b[UC_MCONTEXT..UC_SIGMASK], &mut regs);
    let fpu = if fpstate == 0 {
        FpuState::default()
    } else {
        match cx.read_bytes(fpstate, FpuState::SIZE) {
            Ok(fp) => {
                let mut a = [0u8; FpuState::SIZE];
                a.copy_from_slice(&fp);
                FpuState::from_bytes(&a)
            }
            Err(_) => {
                cx.thread.force_signal(SigInfo::new(SIGSEGV, SI_KERNEL, 0));
                return Ok(0);
            }
        }
    };
    regs.set_fpu(fpu);
    *cx.regs = regs;
    cx.thread.set_blocked(SigSet(get(&b, UC_SIGMASK)));
    // The call that the handler interrupted does not continue, as in Linux.
    cx.thread.set_restart(None);
    let flags =
        u32::from_ne_bytes([b[UC_STACK + 8], b[UC_STACK + 9], b[UC_STACK + 10], b[UC_STACK + 11]]);
    let stack = AltStack { sp: get(&b, UC_STACK), size: get(&b, UC_STACK + 16), flags };
    let _ = set_altstack(cx.thread, stack, cx.regs.regs().rsp);
    Ok(cx.regs.regs().rax)
}
