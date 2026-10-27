//! The system call table: each number goes to its handler.

use crate::cx::{Cx, SysResult};
use crate::{
    aio, cred, epoll, eventfd, fanotify, fhandle, fs, futex, info, inotify, memfd, mm, mount,
    mqueue, msg, net, pidfd, poll, process, ptrace, sched, seccomp, sem, shm, signal, signalfd,
    splice, statmount, swap, timer, timerfd, xattr,
};
use rk_abi::Errno;
use rk_abi::native::syscalls as nr;

/// Handles the system call in the registers of `cx` and puts the return value in them.
pub(crate) fn dispatch(cx: &mut Cx<'_>) {
    let number = cx.number;
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
        #[cfg(target_arch = "x86_64")]
        nr::POLL => poll::poll(cx, a[0], a[1], a[2]),
        nr::PPOLL => poll::ppoll(cx, a[0], a[1], a[2], a[3], a[4]),
        #[cfg(target_arch = "x86_64")]
        nr::SELECT => poll::select(cx, a[0], a[1], a[2], a[3], a[4]),
        nr::PSELECT6 => poll::pselect6(cx, a[0], a[1], a[2], a[3], a[4], a[5]),
        #[cfg(target_arch = "x86_64")]
        nr::PIPE => poll::pipe(cx, a[0]),
        nr::PIPE2 => poll::pipe2(cx, a[0], a[1]),
        #[cfg(target_arch = "x86_64")]
        nr::EPOLL_CREATE => epoll::epoll_create(cx, a[0]),
        nr::EPOLL_CREATE1 => epoll::epoll_create1(cx, a[0]),
        nr::EPOLL_CTL => epoll::epoll_ctl(cx, a[0], a[1], a[2], a[3]),
        #[cfg(target_arch = "x86_64")]
        nr::EPOLL_WAIT => epoll::epoll_wait(cx, a[0], a[1], a[2], a[3]),
        nr::EPOLL_PWAIT => epoll::epoll_pwait(cx, a[0], a[1], a[2], a[3], a[4], a[5]),
        nr::EPOLL_PWAIT2 => epoll::epoll_pwait2(cx, a[0], a[1], a[2], a[3], a[4], a[5]),
        #[cfg(target_arch = "x86_64")]
        nr::EVENTFD => eventfd::eventfd(cx, a[0]),
        nr::EVENTFD2 => eventfd::eventfd2(cx, a[0], a[1]),
        nr::IO_SETUP => aio::io_setup(cx, a[0], a[1]),
        nr::IO_DESTROY => aio::io_destroy(cx, a[0]),
        nr::IO_SUBMIT => aio::io_submit(cx, a[0], a[1], a[2]),
        nr::IO_CANCEL => aio::io_cancel(cx, a[0], a[1], a[2]),
        nr::IO_GETEVENTS => aio::io_getevents(cx, a[0], a[1], a[2], a[3], a[4]),
        nr::IO_PGETEVENTS => aio::io_pgetevents(cx, &a),
        nr::TIMERFD_CREATE => timerfd::timerfd_create(cx, a[0], a[1]),
        nr::TIMERFD_SETTIME => timerfd::timerfd_settime(cx, a[0], a[1], a[2], a[3]),
        nr::TIMERFD_GETTIME => timerfd::timerfd_gettime(cx, a[0], a[1]),
        #[cfg(target_arch = "x86_64")]
        nr::SIGNALFD => signalfd::signalfd(cx, a[0], a[1], a[2]),
        nr::SIGNALFD4 => signalfd::signalfd4(cx, a[0], a[1], a[2], a[3]),
        #[cfg(target_arch = "x86_64")]
        nr::OPEN => fs::openat(cx, at_fdcwd(), a[0], a[1], a[2]),
        nr::CLOSE => fs::close(cx, a[0]),
        #[cfg(target_arch = "x86_64")]
        nr::STAT => fs::fstatat(cx, at_fdcwd(), a[0], a[1], 0),
        nr::FSTAT => fs::fstat(cx, a[0], a[1]),
        #[cfg(target_arch = "x86_64")]
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
        nr::PREADV => fs::preadv(cx, a[0], a[1], a[2], a[3]),
        nr::PWRITEV => fs::pwritev(cx, a[0], a[1], a[2], a[3]),
        nr::PREADV2 => fs::preadv2(cx, a[0], a[1], a[2], a[3], a[5]),
        nr::PWRITEV2 => fs::pwritev2(cx, a[0], a[1], a[2], a[3], a[5]),
        #[cfg(target_arch = "x86_64")]
        nr::ACCESS => fs::faccessat(cx, at_fdcwd(), a[0], a[1], 0),
        nr::SCHED_YIELD => process::sched_yield(),
        nr::GETPRIORITY => sched::getpriority(cx, a[0], a[1]),
        nr::SETPRIORITY => sched::setpriority(cx, a[0], a[1], a[2]),
        nr::SCHED_SETPARAM => sched::sched_setparam(cx, a[0], a[1]),
        nr::SCHED_GETPARAM => sched::sched_getparam(cx, a[0], a[1]),
        nr::SCHED_SETSCHEDULER => sched::sched_setscheduler(cx, a[0], a[1], a[2]),
        nr::SCHED_GETSCHEDULER => sched::sched_getscheduler(cx, a[0]),
        nr::SCHED_GET_PRIORITY_MAX => sched::sched_get_priority_max(a[0]),
        nr::SCHED_GET_PRIORITY_MIN => sched::sched_get_priority_min(a[0]),
        nr::SCHED_RR_GET_INTERVAL => sched::sched_rr_get_interval(cx, a[0], a[1]),
        nr::SCHED_SETAFFINITY => sched::sched_setaffinity(cx, a[0], a[1], a[2]),
        nr::SCHED_GETAFFINITY => sched::sched_getaffinity(cx, a[0], a[1], a[2]),
        nr::SCHED_SETATTR => sched::sched_setattr(cx, a[0], a[1], a[2]),
        nr::SCHED_GETATTR => sched::sched_getattr(cx, a[0], a[1], a[2], a[3]),
        nr::GETCPU => sched::getcpu(cx, a[0], a[1]),
        nr::MADVISE => mm::madvise(cx, a[0], a[1], a[2]),
        #[cfg(target_arch = "x86_64")]
        nr::PAUSE => signal::pause(cx),
        nr::DUP => fs::dup(cx, a[0]),
        #[cfg(target_arch = "x86_64")]
        nr::DUP2 => fs::dup2(cx, a[0], a[1]),
        nr::GETPID => Ok(u64::from(cx.process().pid())),
        #[cfg(target_arch = "x86_64")]
        nr::CLONE => process::clone(cx, a[0], a[1], a[2], a[3], a[4]),
        // arm64 has the order of `CONFIG_CLONE_BACKWARDS`: the TLS comes before the child TID.
        #[cfg(target_arch = "aarch64")]
        nr::CLONE => process::clone(cx, a[0], a[1], a[2], a[4], a[3]),
        nr::CLONE3 => process::clone3(cx, a[0], a[1]),
        nr::SEMGET => sem::semget(cx, a[0], a[1], a[2]),
        nr::SEMOP => sem::semop(cx, a[0], a[1], a[2]),
        nr::SEMTIMEDOP => sem::semtimedop(cx, a[0], a[1], a[2], a[3]),
        nr::SEMCTL => sem::semctl(cx, a[0], a[1], a[2], a[3]),
        nr::SHMGET => shm::shmget(cx, a[0], a[1], a[2]),
        nr::SHMAT => shm::shmat(cx, a[0], a[1], a[2]),
        nr::SHMDT => shm::shmdt(cx, a[0]),
        nr::SHMCTL => shm::shmctl(cx, a[0], a[1], a[2]),
        nr::MSGGET => msg::msgget(cx, a[0], a[1]),
        nr::MSGSND => msg::msgsnd(cx, a[0], a[1], a[2], a[3]),
        nr::MSGRCV => msg::msgrcv(cx, a[0], a[1], a[2], a[3], a[4]),
        nr::MSGCTL => msg::msgctl(cx, a[0], a[1], a[2]),
        nr::MQ_OPEN => mqueue::mq_open(cx, a[0], a[1], a[2], a[3]),
        nr::MQ_UNLINK => mqueue::mq_unlink(cx, a[0]),
        nr::MQ_TIMEDSEND => mqueue::mq_timedsend(cx, a[0], a[1], a[2], a[3], a[4]),
        nr::MQ_TIMEDRECEIVE => mqueue::mq_timedreceive(cx, a[0], a[1], a[2], a[3], a[4]),
        nr::MQ_NOTIFY => mqueue::mq_notify(cx, a[0], a[1]),
        nr::MQ_GETSETATTR => mqueue::mq_getsetattr(cx, a[0], a[1], a[2]),
        nr::MEMFD_CREATE => memfd::memfd_create(cx, a[0], a[1]),
        nr::SOCKET => net::socket_call(cx, a[0], a[1], a[2]),
        nr::SOCKETPAIR => net::socketpair(cx, a[0], a[1], a[2], a[3]),
        nr::BIND => net::bind(cx, a[0], a[1], a[2]),
        nr::CONNECT => net::connect(cx, a[0], a[1], a[2]),
        nr::LISTEN => net::listen(cx, a[0], a[1]),
        nr::ACCEPT => net::accept4(cx, a[0], a[1], a[2], 0),
        nr::ACCEPT4 => net::accept4(cx, a[0], a[1], a[2], a[3]),
        nr::GETSOCKNAME => net::getsockname(cx, a[0], a[1], a[2]),
        nr::GETPEERNAME => net::getpeername(cx, a[0], a[1], a[2]),
        nr::SENDTO => net::sendto(cx, a[0], a[1], a[2], a[3], a[4], a[5]),
        nr::RECVFROM => net::recvfrom(cx, a[0], a[1], a[2], a[3], a[4], a[5]),
        nr::SENDMSG => net::sendmsg(cx, a[0], a[1], a[2]),
        nr::RECVMSG => net::recvmsg(cx, a[0], a[1], a[2]),
        nr::SENDMMSG => net::sendmmsg(cx, a[0], a[1], a[2], a[3]),
        nr::RECVMMSG => net::recvmmsg(cx, a[0], a[1], a[2], a[3], a[4]),
        nr::SHUTDOWN => net::shutdown(cx, a[0], a[1]),
        nr::GETSOCKOPT => net::getsockopt(cx, a[0], a[1], a[2], a[3], a[4]),
        nr::SETSOCKOPT => net::setsockopt(cx, a[0], a[1], a[2], a[3], a[4]),
        nr::UNSHARE => process::unshare(cx, a[0]),
        #[cfg(target_arch = "x86_64")]
        nr::FORK => process::fork(cx),
        #[cfg(target_arch = "x86_64")]
        nr::VFORK => process::vfork(cx),
        nr::EXECVE => process::execve(cx, a[0], a[1], a[2]),
        nr::EXECVEAT => process::execveat(cx, a[0], a[1], a[2], a[3], a[4]),
        nr::EXIT => process::exit(cx, a[0]),
        nr::WAIT4 => process::wait4(cx, a[0], a[1], a[2], a[3]),
        nr::PTRACE => ptrace::ptrace(cx, a[0], a[1], a[2], a[3]),
        nr::PROCESS_VM_READV => ptrace::process_vm_readv(cx, a[0], a[1], a[2], a[3], a[4], a[5]),
        nr::PROCESS_VM_WRITEV => ptrace::process_vm_writev(cx, a[0], a[1], a[2], a[3], a[4], a[5]),
        nr::WAITID => process::waitid(cx, a[0], a[1], a[2], a[3], a[4]),
        nr::KILL => signal::kill(cx, a[0], a[1]),
        nr::UNAME => info::uname(cx, a[0]),
        nr::SYSLOG => info::syslog(cx, a[0], a[1], a[2]),
        nr::FCNTL => fs::fcntl(cx, a[0], a[1], a[2]),
        nr::FLOCK => fs::flock(cx, a[0], a[1]),
        nr::FSYNC | nr::FDATASYNC => cx.file(a[0]).and_then(|f| f.sync().map(|()| 0)),
        nr::TRUNCATE => fs::truncate(cx, a[0], a[1]),
        nr::FTRUNCATE => fs::ftruncate(cx, a[0], a[1]),
        nr::FALLOCATE => fs::fallocate(cx, a[0], a[1], a[2], a[3]),
        nr::SYNC_FILE_RANGE => fs::sync_file_range(cx, a[0], a[1], a[2], a[3]),
        nr::GETCWD => fs::getcwd(cx, a[0], a[1]),
        nr::CHDIR => fs::chdir(cx, a[0]),
        nr::FCHDIR => fs::fchdir(cx, a[0]),
        #[cfg(target_arch = "x86_64")]
        nr::RENAME => fs::renameat2(cx, at_fdcwd(), a[0], at_fdcwd(), a[1], 0),
        #[cfg(target_arch = "x86_64")]
        nr::MKDIR => fs::mkdirat(cx, at_fdcwd(), a[0], a[1]),
        #[cfg(target_arch = "x86_64")]
        nr::RMDIR => {
            fs::unlinkat(cx, at_fdcwd(), a[0], u64::from(rk_abi::native::at::AT_REMOVEDIR as u32))
        }
        #[cfg(target_arch = "x86_64")]
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
        #[cfg(target_arch = "x86_64")]
        nr::LINK => fs::linkat(cx, at_fdcwd(), a[0], at_fdcwd(), a[1], 0),
        #[cfg(target_arch = "x86_64")]
        nr::UNLINK => fs::unlinkat(cx, at_fdcwd(), a[0], 0),
        #[cfg(target_arch = "x86_64")]
        nr::SYMLINK => fs::symlinkat(cx, a[0], at_fdcwd(), a[1]),
        #[cfg(target_arch = "x86_64")]
        nr::READLINK => fs::readlinkat(cx, at_fdcwd(), a[0], a[1], a[2]),
        #[cfg(target_arch = "x86_64")]
        nr::CHMOD => fs::fchmodat(cx, at_fdcwd(), a[0], a[1]),
        nr::FCHMOD => fs::fchmod(cx, a[0], a[1]),
        #[cfg(target_arch = "x86_64")]
        nr::CHOWN => fs::fchownat(cx, at_fdcwd(), a[0], a[1], a[2], 0),
        #[cfg(target_arch = "x86_64")]
        nr::LCHOWN => fs::fchownat(
            cx,
            at_fdcwd(),
            a[0],
            a[1],
            a[2],
            u64::from(rk_abi::native::at::AT_SYMLINK_NOFOLLOW as u32),
        ),
        nr::SETXATTR => xattr::path_setxattr(cx, a[0], a[1], a[2], a[3], a[4], true),
        nr::LSETXATTR => xattr::path_setxattr(cx, a[0], a[1], a[2], a[3], a[4], false),
        nr::FSETXATTR => xattr::fsetxattr(cx, a[0], a[1], a[2], a[3], a[4]),
        nr::GETXATTR => xattr::path_getxattr(cx, a[0], a[1], a[2], a[3], true),
        nr::LGETXATTR => xattr::path_getxattr(cx, a[0], a[1], a[2], a[3], false),
        nr::FGETXATTR => xattr::fgetxattr(cx, a[0], a[1], a[2], a[3]),
        nr::LISTXATTR => xattr::path_listxattr(cx, a[0], a[1], a[2], true),
        nr::LLISTXATTR => xattr::path_listxattr(cx, a[0], a[1], a[2], false),
        nr::FLISTXATTR => xattr::flistxattr(cx, a[0], a[1], a[2]),
        nr::REMOVEXATTR => xattr::path_removexattr(cx, a[0], a[1], true),
        nr::LREMOVEXATTR => xattr::path_removexattr(cx, a[0], a[1], false),
        nr::FREMOVEXATTR => xattr::fremovexattr(cx, a[0], a[1]),
        nr::FCHOWN => fs::fchown(cx, a[0], a[1], a[2]),
        nr::UMASK => fs::umask(cx, a[0]),
        nr::GETTIMEOFDAY => info::gettimeofday(cx, a[0], a[1]),
        nr::SETTIMEOFDAY => info::settimeofday(cx, a[0], a[1]),
        nr::ADJTIMEX => info::adjtimex(cx, a[0]),
        nr::SETHOSTNAME => info::sethostname(cx, a[0], a[1]),
        nr::SETDOMAINNAME => info::setdomainname(cx, a[0], a[1]),
        nr::GETRLIMIT => info::prlimit64(cx, 0, a[0], 0, a[1]),
        nr::SETRLIMIT => info::prlimit64(cx, 0, a[0], a[1], 0),
        nr::GETRUSAGE => info::getrusage(cx, a[0], a[1]),
        nr::SYSINFO => info::sysinfo(cx, a[0]),
        nr::TIMES => info::times(cx, a[0]),
        nr::GETUID => cred::getuid(cx),
        nr::GETGID => cred::getgid(cx),
        nr::GETEUID => cred::geteuid(cx),
        nr::GETEGID => cred::getegid(cx),
        nr::SETUID => cred::setuid(cx, a[0]),
        nr::SETGID => cred::setgid(cx, a[0]),
        nr::SETREUID => cred::setreuid(cx, a[0], a[1]),
        nr::SETREGID => cred::setregid(cx, a[0], a[1]),
        nr::SETRESUID => cred::setresuid(cx, a[0], a[1], a[2]),
        nr::SETRESGID => cred::setresgid(cx, a[0], a[1], a[2]),
        nr::GETRESUID => cred::getresid(cx, false, a[0], a[1], a[2]),
        nr::GETRESGID => cred::getresid(cx, true, a[0], a[1], a[2]),
        nr::SETFSUID => cred::setfsuid(cx, a[0]),
        nr::SETFSGID => cred::setfsgid(cx, a[0]),
        nr::GETGROUPS => cred::getgroups(cx, a[0], a[1]),
        nr::SETGROUPS => cred::setgroups(cx, a[0], a[1]),
        nr::SETPGID => process::setpgid(cx, a[0], a[1]),
        nr::GETPPID => Ok(u64::from(cx.process().ppid())),
        #[cfg(target_arch = "x86_64")]
        nr::GETPGRP => Ok(u64::from(cx.process().pgid())),
        nr::SETSID => cx.process().set_sid().map(u64::from),
        nr::GETPGID => process::getpgid(cx, a[0]),
        nr::GETSID => process::getsid(cx, a[0]),
        nr::SIGALTSTACK => signal::sigaltstack(cx, a[0], a[1]),
        nr::RT_SIGPENDING => signal::rt_sigpending(cx, a[0], a[1]),
        nr::RT_SIGSUSPEND => signal::rt_sigsuspend(cx, a[0], a[1]),
        #[cfg(target_arch = "x86_64")]
        nr::MKNOD => fs::mknodat(cx, at_fdcwd(), a[0], a[1], a[2]),
        nr::STATFS => fs::statfs(cx, a[0], a[1]),
        nr::MOUNT => mount::mount(cx, a[0], a[1], a[2], a[3], a[4]),
        nr::SWAPON => swap::swapon(cx, a[0], a[1]),
        nr::SWAPOFF => swap::swapoff(cx, a[0]),
        nr::UMOUNT2 => mount::umount2(cx, a[0], a[1]),
        nr::FSOPEN => mount::fsopen(cx, a[0], a[1]),
        nr::FSCONFIG => mount::fsconfig(cx, a[0], a[1], a[2], a[3], a[4]),
        nr::FSMOUNT => mount::fsmount(cx, a[0], a[1], a[2]),
        nr::FSPICK => mount::fspick(cx, a[0], a[1], a[2]),
        nr::MOVE_MOUNT => mount::move_mount(cx, a[0], a[1], a[2], a[3], a[4]),
        nr::OPEN_TREE => mount::open_tree(cx, a[0], a[1], a[2]),
        nr::MOUNT_SETATTR => mount::mount_setattr(cx, a[0], a[1], a[2], a[3], a[4]),
        nr::PIVOT_ROOT => mount::pivot_root(cx, a[0], a[1]),
        nr::STATMOUNT => statmount::statmount(cx, a[0], a[1], a[2], a[3]),
        nr::LISTMOUNT => statmount::listmount(cx, a[0], a[1], a[2], a[3]),
        nr::FSTATFS => fs::fstatfs(cx, a[0], a[1]),
        nr::PRCTL => process::prctl(cx, a[0], [a[1], a[2], a[3], a[4]]),
        nr::SECCOMP => seccomp::seccomp(cx, a[0], a[1], a[2]),
        #[cfg(target_arch = "x86_64")]
        nr::ARCH_PRCTL => process::arch_prctl(cx, a[0], a[1]),
        nr::SYNC => {
            // `sync` does not give an error, as in Linux.
            if let Ok(fs) = cx.fs() {
                for m in fs.namespace().mounts() {
                    let _ = m.root().inode().sync();
                }
            }
            let _ = rk_vfs::blockdev::sync_all();
            Ok(0)
        }
        nr::SYNCFS => cx.file(a[0]).and_then(|f| {
            if let Some(inode) = f.inode() {
                inode.sync()?;
            }
            rk_vfs::blockdev::sync_all().map(|()| 0)
        }),
        nr::GETTID => Ok(u64::from(cx.thread.tid())),
        nr::TKILL => signal::tkill(cx, a[0], a[1]),
        #[cfg(target_arch = "x86_64")]
        nr::ALARM => timer::alarm(cx, a[0]),
        nr::GETITIMER => timer::getitimer(cx, a[0], a[1]),
        nr::SETITIMER => timer::setitimer(cx, a[0], a[1], a[2]),
        nr::TIMER_CREATE => timer::timer_create(cx, a[0], a[1], a[2]),
        nr::TIMER_SETTIME => timer::timer_settime(cx, a[0], a[1], a[2], a[3]),
        nr::TIMER_GETTIME => timer::timer_gettime(cx, a[0], a[1]),
        nr::TIMER_GETOVERRUN => timer::timer_getoverrun(cx, a[0]),
        nr::TIMER_DELETE => timer::timer_delete(cx, a[0]),
        nr::RT_SIGTIMEDWAIT => signal::rt_sigtimedwait(cx, a[0], a[1], a[2], a[3]),
        nr::RT_SIGQUEUEINFO => signal::rt_sigqueueinfo(cx, a[0], a[1], a[2]),
        nr::RT_TGSIGQUEUEINFO => signal::rt_tgsigqueueinfo(cx, a[0], a[1], a[2], a[3]),
        #[cfg(target_arch = "x86_64")]
        nr::TIME => info::time(cx, a[0]),
        nr::SET_TID_ADDRESS => {
            cx.thread.set_clear_child_tid(a[0] as usize);
            Ok(u64::from(cx.thread.tid()))
        }
        nr::GETDENTS64 => fs::getdents64(cx, a[0], a[1], a[2]),
        nr::CLOCK_GETTIME => info::clock_gettime(cx, a[0], a[1]),
        nr::CLOCK_SETTIME => info::clock_settime(cx, a[0], a[1]),
        nr::CLOCK_ADJTIME => info::clock_adjtime(cx, a[0], a[1]),
        nr::CLOCK_GETRES => info::clock_getres(cx, a[0], a[1]),
        nr::CLOCK_NANOSLEEP => info::clock_nanosleep(cx, a[0], a[1], a[2], a[3]),
        nr::NANOSLEEP => info::clock_nanosleep(cx, 0, 0, a[0], a[1]),
        nr::RESTART_SYSCALL => info::restart_syscall(cx),
        nr::EXIT_GROUP => process::exit_group(cx, a[0]),
        nr::TGKILL => signal::tgkill(cx, a[0], a[1], a[2]),
        nr::OPENAT => fs::openat(cx, a[0], a[1], a[2], a[3]),
        nr::OPENAT2 => fs::openat2(cx, a[0], a[1], a[2], a[3]),
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
        nr::FCHMODAT2 => fs::fchmodat2(cx, a[0], a[1], a[2], a[3]),
        nr::CLOSE_RANGE => fs::close_range(cx, a[0], a[1], a[2]),
        nr::CACHESTAT => fs::cachestat(cx, a[0], a[1], a[2], a[3]),
        nr::CHROOT => fs::chroot(cx, a[0]),
        #[cfg(target_arch = "x86_64")]
        nr::INOTIFY_INIT => inotify::inotify_init(cx),
        nr::INOTIFY_INIT1 => inotify::inotify_init1(cx, a[0]),
        nr::INOTIFY_ADD_WATCH => inotify::inotify_add_watch(cx, a[0], a[1], a[2]),
        nr::INOTIFY_RM_WATCH => inotify::inotify_rm_watch(cx, a[0], a[1]),
        nr::FANOTIFY_INIT => fanotify::fanotify_init(cx, a[0], a[1]),
        nr::FANOTIFY_MARK => fanotify::fanotify_mark(cx, a[0], a[1], a[2], a[3], a[4]),
        nr::FACCESSAT => fs::faccessat(cx, a[0], a[1], a[2], 0),
        nr::FACCESSAT2 => fs::faccessat(cx, a[0], a[1], a[2], a[3]),
        nr::SET_ROBUST_LIST => futex::set_robust_list(cx, a[0], a[1]),
        nr::GET_ROBUST_LIST => futex::get_robust_list(cx, a[0], a[1], a[2]),
        nr::FUTEX => futex::futex(cx, a[0], a[1], a[2], a[3], a[4], a[5]),
        nr::UTIMENSAT => fs::utimensat(cx, a[0], a[1], a[2], a[3]),
        nr::DUP3 => fs::dup3(cx, a[0], a[1], a[2]),
        nr::PRLIMIT64 => info::prlimit64(cx, a[0], a[1], a[2], a[3]),
        nr::RENAMEAT2 => fs::renameat2(cx, a[0], a[1], a[2], a[3], a[4]),
        nr::GETRANDOM => info::getrandom(cx, a[0], a[1], a[2]),
        nr::MEMBARRIER => mm::membarrier(cx, a[0], a[1], a[2]),
        nr::STATX => fs::statx(cx, a[0], a[1], a[2], a[3], a[4]),
        nr::NAME_TO_HANDLE_AT => fhandle::name_to_handle_at(cx, a[0], a[1], a[2], a[3], a[4]),
        nr::OPEN_BY_HANDLE_AT => fhandle::open_by_handle_at(cx, a[0], a[1], a[2]),
        nr::CAPGET => cred::capget(cx, a[0], a[1]),
        nr::CAPSET => cred::capset(cx, a[0], a[1]),
        nr::KCMP => process::kcmp(a[0], a[1], a[2], a[3], a[4]),
        nr::PIDFD_OPEN => pidfd::pidfd_open(cx, a[0], a[1]),
        nr::PIDFD_SEND_SIGNAL => pidfd::pidfd_send_signal(cx, a[0], a[1], a[2], a[3]),
        nr::SENDFILE => splice::sendfile(cx, a[0], a[1], a[2], a[3]),
        nr::SPLICE => splice::splice(cx, a[0], a[1], a[2], a[3], a[4], a[5]),
        nr::COPY_FILE_RANGE => splice::copy_file_range(cx, a[0], a[1], a[2], a[3], a[4], a[5]),
        nr::FADVISE64 => splice::fadvise64(cx, a[0], a[1], a[2], a[3]),
        nr::PIDFD_GETFD => pidfd::pidfd_getfd(cx, a[0], a[1], a[2]),
        _ => Err(Errno::ENOSYS),
    }
}

/// `AT_FDCWD` as a register value.
#[cfg(target_arch = "x86_64")]
fn at_fdcwd() -> u64 {
    rk_abi::native::at::AT_FDCWD as i64 as u64
}

/// `AT_SYMLINK_NOFOLLOW` as a register value.
#[cfg(target_arch = "x86_64")]
fn symlink_nofollow() -> u64 {
    rk_abi::native::at::AT_SYMLINK_NOFOLLOW as u64
}
