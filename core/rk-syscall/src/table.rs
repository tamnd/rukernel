//! The system call table: each number goes to its handler.

use crate::cx::{Cx, SysResult};
use crate::{fs, futex, info, mm, mount, poll, process, signal};
use rk_abi::Errno;
use rk_abi::native::syscalls as nr;

/// Handles the system call in the registers of `cx` and puts the return value in them.
pub(crate) fn dispatch(cx: &mut Cx<'_>) {
    let number = cx.regs.syscall_number();
    let args = cx.regs.syscall_args();
    let ret = match u32::try_from(number) {
        Ok(n) => handle(cx, n, args),
        Err(_) => Err(Errno::ENOSYS),
    };
    let value = match ret {
        Ok(v) => v,
        Err(e) => e.to_syscall_return() as u64,
    };
    cx.regs.set_syscall_return(value);
}

/// Runs the handler of the system call `n`.
fn handle(cx: &mut Cx<'_>, n: u32, a: [u64; 6]) -> SysResult {
    match n {
        nr::READ => fs::read(cx, a[0], a[1], a[2]),
        nr::WRITE => fs::write(cx, a[0], a[1], a[2]),
        nr::POLL => poll::poll(cx, a[0], a[1], a[2]),
        nr::PPOLL => poll::ppoll(cx, a[0], a[1], a[2], a[3], a[4]),
        nr::SELECT => poll::select(cx, a[0], a[1], a[2], a[3], a[4]),
        nr::PSELECT6 => poll::pselect6(cx, a[0], a[1], a[2], a[3], a[4], a[5]),
        nr::PIPE => poll::pipe(cx, a[0]),
        nr::PIPE2 => poll::pipe2(cx, a[0], a[1]),
        nr::OPEN => fs::openat(cx, at_fdcwd(), a[0], a[1], a[2]),
        nr::CLOSE => fs::close(cx, a[0]),
        nr::STAT => fs::fstatat(cx, at_fdcwd(), a[0], a[1], 0),
        nr::FSTAT => fs::fstat(cx, a[0], a[1]),
        nr::LSTAT => fs::fstatat(cx, at_fdcwd(), a[0], a[1], symlink_nofollow()),
        nr::LSEEK => fs::lseek(cx, a[0], a[1], a[2]),
        nr::MMAP => mm::mmap(cx, a[0], a[1], a[2], a[3], a[4], a[5]),
        nr::MPROTECT => mm::mprotect(cx, a[0], a[1], a[2]),
        nr::MUNMAP => mm::munmap(cx, a[0], a[1]),
        nr::MSYNC => mm::msync(cx, a[0], a[1], a[2]),
        nr::MLOCK => mm::mlock(cx, a[0], a[1]),
        nr::MLOCK2 => mm::mlock2(cx, a[0], a[1], a[2]),
        nr::MUNLOCK => mm::munlock(cx, a[0], a[1]),
        nr::MLOCKALL => mm::mlockall(cx, a[0]),
        nr::MUNLOCKALL => mm::munlockall(cx),
        nr::MINCORE => mm::mincore(cx, a[0], a[1], a[2]),
        nr::MREMAP => mm::mremap(cx, a[0], a[1], a[2], a[3], a[4]),
        nr::BRK => mm::brk(cx, a[0]),
        nr::RT_SIGACTION => signal::rt_sigaction(cx, a[0], a[1], a[2], a[3]),
        nr::RT_SIGPROCMASK => signal::rt_sigprocmask(cx, a[0], a[1], a[2], a[3]),
        nr::RT_SIGRETURN => signal::rt_sigreturn(cx),
        nr::IOCTL => fs::ioctl(cx, a[0], a[1], a[2]),
        nr::PREAD64 => fs::pread(cx, a[0], a[1], a[2], a[3]),
        nr::PWRITE64 => fs::pwrite(cx, a[0], a[1], a[2], a[3]),
        nr::READV => fs::readv(cx, a[0], a[1], a[2]),
        nr::WRITEV => fs::writev(cx, a[0], a[1], a[2]),
        nr::ACCESS => fs::faccessat(cx, at_fdcwd(), a[0], a[1], 0),
        nr::SCHED_YIELD => process::sched_yield(),
        nr::MADVISE => mm::madvise(cx, a[0], a[1], a[2]),
        nr::PAUSE => signal::pause(cx),
        nr::DUP => fs::dup(cx, a[0]),
        nr::DUP2 => fs::dup2(cx, a[0], a[1]),
        nr::GETPID => Ok(u64::from(cx.process().pid())),
        nr::CLONE => process::clone(cx, a[0], a[1], a[2], a[3], a[4]),
        nr::FORK => process::fork(cx),
        nr::VFORK => process::vfork(cx),
        nr::EXECVE => process::execve(cx, a[0], a[1], a[2]),
        nr::EXIT => process::exit(cx, a[0]),
        nr::WAIT4 => process::wait4(cx, a[0], a[1], a[2], a[3]),
        nr::KILL => signal::kill(cx, a[0], a[1]),
        nr::UNAME => info::uname(cx, a[0]),
        nr::FCNTL => fs::fcntl(cx, a[0], a[1], a[2]),
        nr::FSYNC | nr::FDATASYNC => cx.file(a[0]).map(|_| 0),
        nr::TRUNCATE => fs::truncate(cx, a[0], a[1]),
        nr::FTRUNCATE => fs::ftruncate(cx, a[0], a[1]),
        nr::GETCWD => fs::getcwd(cx, a[0], a[1]),
        nr::CHDIR => fs::chdir(cx, a[0]),
        nr::FCHDIR => fs::fchdir(cx, a[0]),
        nr::RENAME => fs::renameat2(cx, at_fdcwd(), a[0], at_fdcwd(), a[1], 0),
        nr::MKDIR => fs::mkdirat(cx, at_fdcwd(), a[0], a[1]),
        nr::RMDIR => {
            fs::unlinkat(cx, at_fdcwd(), a[0], u64::from(rk_abi::native::at::AT_REMOVEDIR as u32))
        }
        nr::CREAT => fs::openat(
            cx,
            at_fdcwd(),
            a[0],
            u64::from(
                rk_abi::native::open::O_CREAT
                    | rk_abi::native::open::O_WRONLY
                    | rk_abi::native::open::O_TRUNC,
            ),
            a[1],
        ),
        nr::LINK => fs::linkat(cx, at_fdcwd(), a[0], at_fdcwd(), a[1], 0),
        nr::UNLINK => fs::unlinkat(cx, at_fdcwd(), a[0], 0),
        nr::SYMLINK => fs::symlinkat(cx, a[0], at_fdcwd(), a[1]),
        nr::READLINK => fs::readlinkat(cx, at_fdcwd(), a[0], a[1], a[2]),
        nr::CHMOD => fs::fchmodat(cx, at_fdcwd(), a[0], a[1]),
        nr::FCHMOD => fs::fchmod(cx, a[0], a[1]),
        nr::CHOWN | nr::LCHOWN => fs::fchownat(cx, at_fdcwd(), a[0], a[1], a[2], 0),
        nr::FCHOWN => fs::fchown(cx, a[0], a[1], a[2]),
        nr::UMASK => fs::umask(cx, a[0]),
        nr::GETTIMEOFDAY => info::gettimeofday(cx, a[0], a[1]),
        nr::GETRLIMIT => info::prlimit64(cx, 0, a[0], 0, a[1]),
        nr::SETRLIMIT => info::prlimit64(cx, 0, a[0], a[1], 0),
        nr::GETRUSAGE => info::getrusage(cx, a[0], a[1]),
        nr::SYSINFO => info::sysinfo(cx, a[0]),
        nr::TIMES => info::times(cx, a[0]),
        nr::GETUID | nr::GETGID | nr::GETEUID | nr::GETEGID => Ok(0),
        nr::SETUID | nr::SETGID | nr::SETREUID | nr::SETREGID | nr::SETRESUID | nr::SETRESGID => {
            Ok(0)
        }
        nr::GETRESUID | nr::GETRESGID => info::getresid(cx, a[0], a[1], a[2]),
        nr::GETGROUPS => Ok(0),
        nr::SETPGID => process::setpgid(cx, a[0], a[1]),
        nr::GETPPID => Ok(u64::from(cx.process().ppid())),
        nr::GETPGRP => Ok(u64::from(cx.process().pgid())),
        nr::SETSID => cx.process().set_sid().map(u64::from),
        nr::GETPGID => process::getpgid(cx, a[0]),
        nr::GETSID => process::getsid(cx, a[0]),
        nr::SIGALTSTACK => signal::sigaltstack(cx, a[0], a[1]),
        nr::RT_SIGPENDING => signal::rt_sigpending(cx, a[0], a[1]),
        nr::RT_SIGSUSPEND => signal::rt_sigsuspend(cx, a[0], a[1]),
        nr::MKNOD => fs::mknodat(cx, at_fdcwd(), a[0], a[1], a[2]),
        nr::STATFS => fs::statfs(cx, a[0], a[1]),
        nr::MOUNT => mount::mount(cx, a[0], a[1], a[2], a[3], a[4]),
        nr::UMOUNT2 => mount::umount2(cx, a[0], a[1]),
        nr::FSTATFS => fs::fstatfs(cx, a[0], a[1]),
        nr::PRCTL => process::prctl(cx, a[0], a[1]),
        nr::ARCH_PRCTL => process::arch_prctl(cx, a[0], a[1]),
        nr::SYNC => Ok(0),
        nr::GETTID => Ok(u64::from(cx.thread.tid())),
        nr::TKILL => signal::tkill(cx, a[0], a[1]),
        nr::TIME => info::time(cx, a[0]),
        nr::SET_TID_ADDRESS => {
            cx.thread.set_clear_child_tid(a[0] as usize);
            Ok(u64::from(cx.thread.tid()))
        }
        nr::GETDENTS64 => fs::getdents64(cx, a[0], a[1], a[2]),
        nr::CLOCK_GETTIME => info::clock_gettime(cx, a[0], a[1]),
        nr::CLOCK_GETRES => info::clock_getres(cx, a[0], a[1]),
        nr::CLOCK_NANOSLEEP => info::clock_nanosleep(cx, a[0], a[1], a[2], a[3]),
        nr::NANOSLEEP => info::clock_nanosleep(cx, 0, 0, a[0], a[1]),
        nr::EXIT_GROUP => process::exit_group(cx, a[0]),
        nr::TGKILL => signal::tgkill(cx, a[0], a[1], a[2]),
        nr::OPENAT => fs::openat(cx, a[0], a[1], a[2], a[3]),
        nr::MKDIRAT => fs::mkdirat(cx, a[0], a[1], a[2]),
        nr::MKNODAT => fs::mknodat(cx, a[0], a[1], a[2], a[3]),
        nr::FCHOWNAT => fs::fchownat(cx, a[0], a[1], a[2], a[3], a[4]),
        nr::NEWFSTATAT => fs::fstatat(cx, a[0], a[1], a[2], a[3]),
        nr::UNLINKAT => fs::unlinkat(cx, a[0], a[1], a[2]),
        nr::RENAMEAT => fs::renameat2(cx, a[0], a[1], a[2], a[3], 0),
        nr::LINKAT => fs::linkat(cx, a[0], a[1], a[2], a[3], a[4]),
        nr::SYMLINKAT => fs::symlinkat(cx, a[0], a[1], a[2]),
        nr::READLINKAT => fs::readlinkat(cx, a[0], a[1], a[2], a[3]),
        nr::FCHMODAT => fs::fchmodat(cx, a[0], a[1], a[2]),
        nr::FACCESSAT => fs::faccessat(cx, a[0], a[1], a[2], 0),
        nr::FACCESSAT2 => fs::faccessat(cx, a[0], a[1], a[2], a[3]),
        nr::SET_ROBUST_LIST => Ok(0),
        nr::FUTEX => futex::futex(cx, a[0], a[1], a[2], a[3], a[4], a[5]),
        nr::UTIMENSAT => fs::utimensat(cx, a[0], a[1], a[2], a[3]),
        nr::DUP3 => fs::dup3(cx, a[0], a[1], a[2]),
        nr::PRLIMIT64 => info::prlimit64(cx, a[0], a[1], a[2], a[3]),
        nr::RENAMEAT2 => fs::renameat2(cx, a[0], a[1], a[2], a[3], a[4]),
        nr::GETRANDOM => info::getrandom(cx, a[0], a[1], a[2]),
        nr::STATX => fs::statx(cx, a[0], a[1], a[2], a[3], a[4]),
        _ => Err(Errno::ENOSYS),
    }
}

/// `AT_FDCWD` as a register value.
fn at_fdcwd() -> u64 {
    rk_abi::native::at::AT_FDCWD as i64 as u64
}

/// `AT_SYMLINK_NOFOLLOW` as a register value.
fn symlink_nofollow() -> u64 {
    rk_abi::native::at::AT_SYMLINK_NOFOLLOW as u64
}
