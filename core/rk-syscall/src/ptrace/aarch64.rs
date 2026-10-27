//! The registers of an arm64 tracee as `ptrace` gives them: `struct user_pt_regs`, as
//! arch/arm64/kernel/ptrace.c of Linux has it. arm64 has no `PTRACE_GETREGS` and no
//! `PTRACE_PEEKUSR`, so the tracer uses `PTRACE_GETREGSET`.

use rk_abi::Errno;
use rk_frame::user::USER_END;
use rk_proc::ptrace::{Ptrace, Stop};

/// The number of words in `struct user_pt_regs`: x0 to x30, sp, pc and pstate.
pub(super) const NREGS: usize = 34;
/// The words of sp, pc and pstate.
const R_SP: usize = 31;
const R_PC: usize = 32;
const R_PSTATE: usize = 33;

/// The PSTATE bits that the tracer can change: the flags NZCV. `valid_user_regs` of Linux does
/// not let the tracer change the exception level or the masks.
const PSTATE_MASK: u64 = 0xf000_0000;

/// Gives `struct user_pt_regs` of the stopped tracee.
pub(super) fn get_regs(pt: &Ptrace, stop: &Stop) -> [u64; NREGS] {
    let r = stop.regs.regs();
    let mut out = [0; NREGS];
    out[..31].copy_from_slice(&r.x);
    out[R_SP] = r.sp;
    out[R_PC] = r.pc;
    out[R_PSTATE] = pt.flags(stop);
    out
}

/// Sets `struct user_pt_regs` of the stopped tracee, for `PTRACE_SETREGSET`. The program counter
/// must be in user space.
pub(super) fn set_regs(pt: &mut Ptrace, stop: &mut Stop, regs: &[u64; NREGS]) -> Result<(), Errno> {
    if regs[R_PC] >= USER_END as u64 {
        return Err(Errno::EIO);
    }
    let r = stop.regs.regs_mut();
    r.x.copy_from_slice(&regs[..31]);
    r.sp = regs[R_SP];
    r.pc = regs[R_PC];
    pt.set_flags(stop, regs[R_PSTATE], PSTATE_MASK);
    Ok(())
}
