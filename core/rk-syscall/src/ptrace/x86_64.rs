//! The registers of an x86-64 tracee as `ptrace` gives them: `struct user_regs_struct` and
//! `struct user`, as arch/x86/kernel/ptrace.c of Linux has them.

use rk_abi::Errno;
use rk_frame::user::USER_END;
use rk_proc::ptrace::{Ptrace, Stop};

/// The number of words in `struct user_regs_struct`.
pub(super) const NREGS: usize = 27;
/// The size of `struct user`, and the offset of `u_debugreg` in it.
const USER_SIZE: u64 = 912;
const USER_DEBUGREG: u64 = 848;

/// The words of `struct user_regs_struct`.
const R_ORIG_RAX: usize = 15;
const R_CS: usize = 17;
const R_EFLAGS: usize = 18;
const R_SS: usize = 20;
const R_FS_BASE: usize = 21;
const R_GS_BASE: usize = 22;

/// The user code and data segments of x86-64.
const USER_CS: u64 = 0x33;
const USER_DS: u64 = 0x2b;

/// The flags that the tracer can change, as `FLAG_MASK` of Linux: CF, PF, AF, ZF, SF, TF, DF,
/// OF, RF and AC.
const FLAG_MASK: u64 = 0x50dd5;

/// Gives `struct user_regs_struct` of the stopped tracee.
pub(super) fn get_regs(pt: &Ptrace, stop: &Stop) -> [u64; NREGS] {
    let r = stop.regs.regs();
    [
        r.r15,
        r.r14,
        r.r13,
        r.r12,
        r.rbp,
        r.rbx,
        r.r11,
        r.r10,
        r.r9,
        r.r8,
        r.rax,
        r.rcx,
        r.rdx,
        r.rsi,
        r.rdi,
        stop.orig_rax,
        r.rip,
        USER_CS,
        pt.flags(stop),
        r.rsp,
        USER_DS,
        stop.regs.fs_base(),
        0,
        0,
        0,
        0,
        0,
    ]
}

/// Tells if `addr` is a canonical address. The return to user mode with a bad address in RIP
/// or the FS base faults in the kernel.
fn canonical(addr: u64) -> bool {
    ((addr as i64) << 16) >> 16 == addr as i64
}

/// Sets the word `i` of `struct user_regs_struct` of the stopped tracee to `value`, as `putreg`
/// of Linux does. rukernel has one code segment, one data segment and no GS base for user mode,
/// so a write to them changes nothing.
fn set_reg(pt: &mut Ptrace, stop: &mut Stop, i: usize, value: u64) -> Result<(), Errno> {
    match i {
        R_ORIG_RAX => stop.orig_rax = value,
        R_EFLAGS => pt.set_flags(stop, value, FLAG_MASK),
        R_FS_BASE => {
            if value >= USER_END as u64 {
                return Err(Errno::EIO);
            }
            stop.regs.set_fs_base(value);
        }
        R_CS | R_SS | R_GS_BASE => {}
        i if i > R_GS_BASE => {}
        _ => {
            let r = stop.regs.regs_mut();
            let field = match i {
                0 => &mut r.r15,
                1 => &mut r.r14,
                2 => &mut r.r13,
                3 => &mut r.r12,
                4 => &mut r.rbp,
                5 => &mut r.rbx,
                6 => &mut r.r11,
                7 => &mut r.r10,
                8 => &mut r.r9,
                9 => &mut r.r8,
                10 => &mut r.rax,
                11 => &mut r.rcx,
                12 => &mut r.rdx,
                13 => &mut r.rsi,
                14 => &mut r.rdi,
                16 => {
                    if !canonical(value) {
                        return Err(Errno::EIO);
                    }
                    &mut r.rip
                }
                _ => &mut r.rsp,
            };
            *field = value;
        }
    }
    Ok(())
}

/// Sets `struct user_regs_struct` of the stopped tracee, for `PTRACE_SETREGS`.
pub(super) fn set_regs(pt: &mut Ptrace, stop: &mut Stop, regs: &[u64; NREGS]) -> Result<(), Errno> {
    if !canonical(regs[16]) || regs[R_FS_BASE] >= USER_END as u64 {
        return Err(Errno::EIO);
    }
    for (i, &value) in regs.iter().enumerate() {
        set_reg(pt, stop, i, value)?;
    }
    Ok(())
}

/// Reads the word at `addr` of `struct user`, for `PTRACE_PEEKUSR`.
pub(super) fn peek_user(pt: &mut Ptrace, stop: &mut Stop, addr: u64) -> Result<u64, Errno> {
    if !addr.is_multiple_of(8) || addr >= USER_SIZE {
        return Err(Errno::EIO);
    }
    let i = (addr / 8) as usize;
    if i < NREGS {
        return Ok(get_regs(pt, stop)[i]);
    }
    Ok(addr.checked_sub(USER_DEBUGREG).map_or(0, |off| pt.debugreg[(off / 8) as usize]))
}

/// Writes the word at `addr` of `struct user`, for `PTRACE_POKEUSR`. The address of a breakpoint
/// in DR0 to DR3 must be in user space, else the write gives `EINVAL`. DR4 and DR5 do not exist
/// and give `EIO`. The other words of `struct user` do not change.
pub(super) fn poke_user(
    pt: &mut Ptrace,
    stop: &mut Stop,
    addr: u64,
    value: u64,
) -> Result<(), Errno> {
    if !addr.is_multiple_of(8) || addr >= USER_SIZE {
        return Err(Errno::EIO);
    }
    let i = (addr / 8) as usize;
    if i < NREGS {
        return set_reg(pt, stop, i, value);
    }
    let Some(n) = addr.checked_sub(USER_DEBUGREG).map(|off| (off / 8) as usize) else {
        return Ok(());
    };
    match n {
        0..=3 if value >= USER_END as u64 => Err(Errno::EINVAL),
        4 | 5 => Err(Errno::EIO),
        _ => {
            pt.debugreg[n] = value;
            Ok(())
        }
    }
}
