//! `ptrace`, `process_vm_readv` and `process_vm_writev`.
//!
//! The tracer reads and changes the registers and the memory of a stopped tracee, and tells it
//! how to continue. The stops and the waits are in `rk_proc::ptrace`. The requests and the layout
//! of `struct user_regs_struct` are those of kernel/ptrace.c and arch/x86/kernel/ptrace.c of
//! Linux.

use crate::cx::{Cx, SysResult};
use crate::fs::read_iovecs;
use alloc::sync::Arc;
use alloc::vec;
use rk_abi::Errno;
use rk_abi::native::signal::SIGSTOP;
use rk_frame::user::{FpuState, USER_END};
use rk_proc::ptrace::{self, PTRACE_O_MASK, Ptrace, Resume, Stop, StopKind};
use rk_proc::signal::{NSIG, SI_USER, SIGINFO_SIZE, SigInfo, SigSet};
use rk_proc::{Pid, Process, Thread};
use zerocopy::IntoBytes;

/// The requests, from include/uapi/linux/ptrace.h.
const PTRACE_TRACEME: u64 = 0;
const PTRACE_PEEKTEXT: u64 = 1;
const PTRACE_PEEKDATA: u64 = 2;
const PTRACE_PEEKUSR: u64 = 3;
const PTRACE_POKETEXT: u64 = 4;
const PTRACE_POKEDATA: u64 = 5;
const PTRACE_POKEUSR: u64 = 6;
const PTRACE_CONT: u64 = 7;
const PTRACE_KILL: u64 = 8;
const PTRACE_SINGLESTEP: u64 = 9;
const PTRACE_GETREGS: u64 = 12;
const PTRACE_SETREGS: u64 = 13;
const PTRACE_GETFPREGS: u64 = 14;
const PTRACE_SETFPREGS: u64 = 15;
const PTRACE_ATTACH: u64 = 16;
const PTRACE_DETACH: u64 = 17;
const PTRACE_SYSCALL: u64 = 24;
const PTRACE_SETOPTIONS: u64 = 0x4200;
const PTRACE_GETEVENTMSG: u64 = 0x4201;
const PTRACE_GETSIGINFO: u64 = 0x4202;
const PTRACE_SETSIGINFO: u64 = 0x4203;
const PTRACE_GETREGSET: u64 = 0x4204;
const PTRACE_SETREGSET: u64 = 0x4205;
const PTRACE_SEIZE: u64 = 0x4206;
const PTRACE_INTERRUPT: u64 = 0x4207;
const PTRACE_LISTEN: u64 = 0x4208;
const PTRACE_GETSIGMASK: u64 = 0x420a;
const PTRACE_SETSIGMASK: u64 = 0x420b;
const PTRACE_GET_SYSCALL_INFO: u64 = 0x420e;

/// The register sets of `PTRACE_GETREGSET`, from include/uapi/linux/elf.h.
const NT_PRSTATUS: u64 = 1;
const NT_PRFPREG: u64 = 2;

/// The number of words in `struct user_regs_struct`.
const NREGS: usize = 27;
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

/// `struct ptrace_syscall_info`: the operations, the architecture and the sizes.
const SYSCALL_INFO_NONE: u8 = 0;
const SYSCALL_INFO_ENTRY: u8 = 1;
const SYSCALL_INFO_EXIT: u8 = 2;
const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
const SYSCALL_INFO_HEADER: usize = 24;
const SYSCALL_INFO_ENTRY_SIZE: usize = 80;
const SYSCALL_INFO_EXIT_SIZE: usize = 33;

/// The largest errno that a system call gives.
const MAX_ERRNO: i64 = 4095;

pub(crate) fn ptrace(cx: &Cx<'_>, request: u64, pid: u64, addr: u64, data: u64) -> SysResult {
    let pid = pid as u32 as Pid;
    match request {
        PTRACE_TRACEME => return ptrace::trace_me(cx.thread).map(|()| 0),
        PTRACE_ATTACH => {
            let thread = rk_proc::find_thread(pid).ok_or(Errno::ESRCH)?;
            ptrace::attach(cx.process(), &thread, false, 0)?;
            thread.send_signal(SigInfo::new(SIGSTOP, SI_USER, cx.process().pid()));
            return Ok(0);
        }
        PTRACE_SEIZE => {
            if addr != 0 || data & !u64::from(PTRACE_O_MASK) != 0 {
                return Err(Errno::EIO);
            }
            let thread = rk_proc::find_thread(pid).ok_or(Errno::ESRCH)?;
            ptrace::attach(cx.process(), &thread, true, data as u32)?;
            return Ok(0);
        }
        _ => {}
    }
    let tracer = cx.process();
    match request {
        PTRACE_KILL => ptrace::kill(tracer, pid).map(|()| 0),
        PTRACE_INTERRUPT => ptrace::interrupt(tracer, pid).map(|()| 0),
        PTRACE_CONT | PTRACE_SYSCALL | PTRACE_SINGLESTEP | PTRACE_DETACH | PTRACE_LISTEN => {
            if data > u64::from(NSIG) {
                return Err(Errno::EIO);
            }
            let how = match request {
                PTRACE_CONT => Resume::Cont,
                PTRACE_SYSCALL => Resume::Syscall,
                PTRACE_SINGLESTEP => Resume::Step,
                PTRACE_LISTEN => Resume::Listen,
                _ => Resume::Detach,
            };
            ptrace::resume(tracer, pid, how, data as u32).map(|()| 0)
        }
        PTRACE_PEEKTEXT | PTRACE_PEEKDATA => {
            let vm = tracee_vm(tracer, pid)?;
            let mut word = [0u8; 8];
            vm.read(addr as usize, &mut word).map_err(|_| Errno::EIO)?;
            cx.write_val(data, &u64::from_ne_bytes(word))?;
            Ok(0)
        }
        PTRACE_POKETEXT | PTRACE_POKEDATA => {
            let vm = tracee_vm(tracer, pid)?;
            vm.write_force(addr as usize, &data.to_ne_bytes()).map_err(|_| Errno::EIO)?;
            Ok(0)
        }
        PTRACE_PEEKUSR => {
            let word = ptrace::with_stopped(tracer, pid, |pt, stop| peek_user(pt, stop, addr))?;
            cx.write_val(data, &word)?;
            Ok(0)
        }
        PTRACE_POKEUSR => {
            ptrace::with_stopped(tracer, pid, |pt, stop| poke_user(pt, stop, addr, data))?;
            Ok(0)
        }
        PTRACE_GETREGS => {
            let regs = ptrace::with_stopped(tracer, pid, |pt, stop| Ok(get_regs(pt, stop)))?;
            cx.write_val(data, &regs)?;
            Ok(0)
        }
        PTRACE_SETREGS => {
            let regs: [u64; NREGS] = cx.read_val(data)?;
            ptrace::with_stopped(tracer, pid, |pt, stop| set_regs(pt, stop, &regs))?;
            Ok(0)
        }
        PTRACE_GETFPREGS => {
            let fpu = ptrace::with_stopped(tracer, pid, |_, stop| Ok(*stop.regs.fpu().as_bytes()))?;
            cx.write_bytes(data, &fpu)?;
            Ok(0)
        }
        PTRACE_SETFPREGS => {
            let fpu: [u8; FpuState::SIZE] = cx.read_val(data)?;
            ptrace::with_stopped(tracer, pid, |_, stop| {
                stop.regs.set_fpu(FpuState::from_bytes(&fpu));
                Ok(())
            })?;
            Ok(0)
        }
        PTRACE_GETREGSET => {
            let iov: rk_abi::native::types::Iovec = cx.read_val(data)?;
            let bytes = ptrace::with_stopped(tracer, pid, |pt, stop| match addr {
                NT_PRSTATUS => Ok(get_regs(pt, stop).as_bytes().to_vec()),
                NT_PRFPREG => Ok(stop.regs.fpu().as_bytes().to_vec()),
                _ => Err(Errno::EINVAL),
            })?;
            let len = bytes.len().min(iov.iov_len as usize);
            cx.write_bytes(iov.iov_base, &bytes[..len])?;
            cx.write_val(data + 8, &(len as u64))?;
            Ok(0)
        }
        PTRACE_SETREGSET => {
            let iov: rk_abi::native::types::Iovec = cx.read_val(data)?;
            let size = match addr {
                NT_PRSTATUS => NREGS * 8,
                NT_PRFPREG => FpuState::SIZE,
                _ => return Err(Errno::EINVAL),
            };
            let len = size.min(iov.iov_len as usize);
            let new = cx.read_bytes(iov.iov_base, len)?;
            ptrace::with_stopped(tracer, pid, |pt, stop| {
                if addr == NT_PRSTATUS {
                    let mut regs = get_regs(pt, stop);
                    regs.as_mut_bytes()[..len].copy_from_slice(&new);
                    set_regs(pt, stop, &regs)
                } else {
                    let mut fpu = *stop.regs.fpu().as_bytes();
                    fpu[..len].copy_from_slice(&new);
                    stop.regs.set_fpu(FpuState::from_bytes(&fpu));
                    Ok(())
                }
            })?;
            cx.write_val(data + 8, &(len as u64))?;
            Ok(0)
        }
        PTRACE_SETOPTIONS => {
            if data & !u64::from(PTRACE_O_MASK) != 0 {
                return Err(Errno::EINVAL);
            }
            ptrace::with_stopped(tracer, pid, |pt, _| {
                pt.options = data as u32;
                Ok(())
            })?;
            Ok(0)
        }
        PTRACE_GETEVENTMSG => {
            let message = ptrace::with_stopped(tracer, pid, |pt, _| Ok(pt.message))?;
            cx.write_val(data, &message)?;
            Ok(0)
        }
        PTRACE_GETSIGINFO => {
            let info = ptrace::with_stopped(tracer, pid, |_, stop| stop.info.ok_or(Errno::EINVAL))?;
            cx.write_bytes(data, &info.to_bytes())?;
            Ok(0)
        }
        PTRACE_SETSIGINFO => {
            let bytes: [u8; SIGINFO_SIZE] = cx.read_val(data)?;
            ptrace::with_stopped(tracer, pid, |_, stop| {
                if stop.info.is_none() {
                    return Err(Errno::EINVAL);
                }
                stop.info = Some(SigInfo::from_bytes(&bytes));
                Ok(())
            })?;
            Ok(0)
        }
        PTRACE_GETSIGMASK => {
            if addr != 8 {
                return Err(Errno::EINVAL);
            }
            let thread = ptrace::stopped_tracee(tracer, pid)?;
            cx.write_val(data, &thread.blocked().0)?;
            Ok(0)
        }
        PTRACE_SETSIGMASK => {
            if addr != 8 {
                return Err(Errno::EINVAL);
            }
            let set: u64 = cx.read_val(data)?;
            let thread = ptrace::stopped_tracee(tracer, pid)?;
            thread.set_blocked(SigSet(set));
            Ok(0)
        }
        PTRACE_GET_SYSCALL_INFO => {
            let info = ptrace::with_stopped(tracer, pid, |_, stop| Ok(syscall_info(stop)))?;
            let (bytes, size) = info;
            let len = size.min(addr as usize);
            cx.write_bytes(data, &bytes[..len])?;
            Ok(size as u64)
        }
        _ => Err(Errno::EIO),
    }
}

/// The address space of the stopped tracee `pid` of `tracer`.
fn tracee_vm(tracer: &Process, pid: Pid) -> Result<Arc<rk_mm::AddressSpace>, Errno> {
    let thread = ptrace::stopped_tracee(tracer, pid)?;
    thread.process().vm().ok_or(Errno::ESRCH)
}

/// Gives `struct user_regs_struct` of the stopped tracee.
fn get_regs(pt: &Ptrace, stop: &Stop) -> [u64; NREGS] {
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
fn set_regs(pt: &mut Ptrace, stop: &mut Stop, regs: &[u64; NREGS]) -> Result<(), Errno> {
    if !canonical(regs[16]) || regs[R_FS_BASE] >= USER_END as u64 {
        return Err(Errno::EIO);
    }
    for (i, &value) in regs.iter().enumerate() {
        set_reg(pt, stop, i, value)?;
    }
    Ok(())
}

/// Reads the word at `addr` of `struct user`, for `PTRACE_PEEKUSR`.
fn peek_user(pt: &mut Ptrace, stop: &mut Stop, addr: u64) -> Result<u64, Errno> {
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
fn poke_user(pt: &mut Ptrace, stop: &mut Stop, addr: u64, value: u64) -> Result<(), Errno> {
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

/// Gives `struct ptrace_syscall_info` of the stopped tracee and its size.
fn syscall_info(stop: &Stop) -> ([u8; SYSCALL_INFO_ENTRY_SIZE], usize) {
    let r = stop.regs.regs();
    let mut b = [0u8; SYSCALL_INFO_ENTRY_SIZE];
    b[4..8].copy_from_slice(&AUDIT_ARCH_X86_64.to_ne_bytes());
    b[8..16].copy_from_slice(&r.rip.to_ne_bytes());
    b[16..24].copy_from_slice(&r.rsp.to_ne_bytes());
    let (op, size) = match stop.kind {
        StopKind::SyscallEntry => {
            let args = [stop.orig_rax, r.rdi, r.rsi, r.rdx, r.r10, r.r8, r.r9];
            for (i, a) in args.iter().enumerate() {
                let at = SYSCALL_INFO_HEADER + i * 8;
                b[at..at + 8].copy_from_slice(&a.to_ne_bytes());
            }
            (SYSCALL_INFO_ENTRY, SYSCALL_INFO_ENTRY_SIZE)
        }
        StopKind::SyscallExit => {
            let rval = r.rax as i64;
            b[24..32].copy_from_slice(&rval.to_ne_bytes());
            b[32] = u8::from((-MAX_ERRNO..0).contains(&rval));
            (SYSCALL_INFO_EXIT, SYSCALL_INFO_EXIT_SIZE)
        }
        _ => (SYSCALL_INFO_NONE, SYSCALL_INFO_HEADER),
    };
    b[0] = op;
    (b, size)
}

/// Copies between the memory of the caller and the memory of the process `pid`, for
/// `process_vm_readv` and `process_vm_writev`. Gives the number of bytes that it copied. A fault
/// in the remote memory ends the copy, and gives an error only if no byte was copied.
fn process_vm(
    cx: &Cx<'_>,
    pid: u64,
    local: (u64, u64),
    remote: (u64, u64),
    flags: u64,
    write: bool,
) -> SysResult {
    if flags != 0 {
        return Err(Errno::EINVAL);
    }
    let local = read_iovecs(cx, local.0, local.1)?;
    let remote = read_iovecs(cx, remote.0, remote.1)?;
    let thread: Arc<Thread> = rk_proc::find_thread(pid as u32).ok_or(Errno::ESRCH)?;
    let other = thread.process().vm().ok_or(Errno::ESRCH)?;
    let me = cx.vm()?;
    let mut buf = vec![0u8; 4096];
    let mut done = 0u64;
    let (mut li, mut loff) = (0, 0u64);
    for r in &remote {
        let mut roff = 0u64;
        while roff < r.iov_len {
            while li < local.len() && loff == local[li].iov_len {
                li += 1;
                loff = 0;
            }
            let Some(l) = local.get(li) else { return Ok(done) };
            let len = (r.iov_len - roff).min(l.iov_len - loff).min(buf.len() as u64) as usize;
            let (laddr, raddr) = ((l.iov_base + loff) as usize, (r.iov_base + roff) as usize);
            let chunk = &mut buf[..len];
            let copied = if write {
                me.read(laddr, chunk)?;
                other.write(raddr, chunk)
            } else {
                other.read(raddr, chunk).and_then(|()| me.write(laddr, chunk))
            };
            if let Err(e) = copied {
                return if done == 0 { Err(e) } else { Ok(done) };
            }
            done += len as u64;
            roff += len as u64;
            loff += len as u64;
        }
    }
    Ok(done)
}

pub(crate) fn process_vm_readv(
    cx: &Cx<'_>,
    pid: u64,
    lvec: u64,
    liovcnt: u64,
    rvec: u64,
    riovcnt: u64,
    flags: u64,
) -> SysResult {
    process_vm(cx, pid, (lvec, liovcnt), (rvec, riovcnt), flags, false)
}

pub(crate) fn process_vm_writev(
    cx: &Cx<'_>,
    pid: u64,
    lvec: u64,
    liovcnt: u64,
    rvec: u64,
    riovcnt: u64,
    flags: u64,
) -> SysResult {
    process_vm(cx, pid, (lvec, liovcnt), (rvec, riovcnt), flags, true)
}
