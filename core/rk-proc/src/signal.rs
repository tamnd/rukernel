//! Signals: the signal sets, the actions, the default actions, the pending queue and `siginfo`.
//!
//! This module is pure code, so the tests on the host examine it. The process code keeps one
//! action table and one shared queue in each process, and one mask and one private queue in each
//! thread, as in Linux.

use alloc::collections::VecDeque;
use rk_abi::native::signal::{
    SIGABRT, SIGBUS, SIGCHLD, SIGCONT, SIGFPE, SIGILL, SIGKILL, SIGQUIT, SIGRTMIN, SIGSEGV,
    SIGSTOP, SIGSYS, SIGTRAP, SIGTSTP, SIGTTIN, SIGTTOU, SIGURG, SIGWINCH, SIGXCPU, SIGXFSZ,
};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// The number of signals. Linux names it `_NSIG`.
pub const NSIG: u32 = 64;

/// The handler value of the default action.
pub const SIG_DFL: u64 = 0;
/// The handler value that ignores the signal.
pub const SIG_IGN: u64 = 1;

/// The `si_code` values that rukernel gives, from include/uapi/asm-generic/siginfo.h.
pub const SI_USER: i32 = 0;
/// The kernel sent the signal.
pub const SI_KERNEL: i32 = 0x80;
/// `sigqueue` sent the signal.
pub const SI_QUEUE: i32 = -1;
/// A POSIX timer sent the signal.
pub const SI_TIMER: i32 = -2;
/// `tkill` or `tgkill` sent the signal.
pub const SI_TKILL: i32 = -6;
/// The child called `exit`.
pub const CLD_EXITED: i32 = 1;
/// A signal killed the child.
pub const CLD_KILLED: i32 = 2;
/// A signal killed the child and it made a core dump.
pub const CLD_DUMPED: i32 = 3;
/// A traced child stopped.
pub const CLD_TRAPPED: i32 = 4;
/// A signal stopped the child.
pub const CLD_STOPPED: i32 = 5;
/// `SIGCONT` continued the stopped child.
pub const CLD_CONTINUED: i32 = 6;
/// The address has no mapping.
pub const SEGV_MAPERR: i32 = 1;
/// The mapping does not permit the access.
pub const SEGV_ACCERR: i32 = 2;
/// The operand of the instruction is not valid.
pub const ILL_ILLOPN: i32 = 2;
/// An integer division by zero.
pub const FPE_INTDIV: i32 = 1;
/// An address that is not aligned.
pub const BUS_ADRALN: i32 = 1;
/// An address that has no data, such as a page of a file mapping past the end of the file.
pub const BUS_ADRERR: i32 = 2;
/// A breakpoint, or a single step over a system call.
pub const TRAP_BRKPT: i32 = 1;
/// A single step.
pub const TRAP_TRACE: i32 = 2;
/// `SIGSYS` from a filter of `seccomp`.
pub const SYS_SECCOMP: i32 = 1;

/// The signals that the kernel gives first, because the program caused them. Linux names this
/// set `SYNCHRONOUS_MASK`.
const SYNCHRONOUS: SigSet = SigSet(
    SigSet::bit(SIGSEGV)
        | SigSet::bit(SIGBUS)
        | SigSet::bit(SIGILL)
        | SigSet::bit(SIGTRAP)
        | SigSet::bit(SIGFPE)
        | SigSet::bit(SIGSYS),
);

/// A set of signals. Bit `n - 1` is the signal `n`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SigSet(pub u64);

impl SigSet {
    /// The set with no signal.
    pub const EMPTY: Self = Self(0);
    /// The signals that stop a process with the default action.
    pub const STOP: Self =
        Self(Self::bit(SIGSTOP) | Self::bit(SIGTSTP) | Self::bit(SIGTTIN) | Self::bit(SIGTTOU));
    /// The signals that a thread cannot block: `SIGKILL` and `SIGSTOP`.
    pub const UNBLOCKABLE: Self = Self(Self::bit(SIGKILL) | Self::bit(SIGSTOP));

    /// The bit of `sig`.
    pub const fn bit(sig: u32) -> u64 {
        1 << (sig - 1)
    }

    /// Tells if `sig` is in the set.
    pub const fn contains(self, sig: u32) -> bool {
        sig >= 1 && sig <= NSIG && self.0 & Self::bit(sig) != 0
    }

    /// Adds `sig` to the set.
    pub fn add(&mut self, sig: u32) {
        self.0 |= Self::bit(sig);
    }

    /// Removes `sig` from the set.
    pub fn remove(&mut self, sig: u32) {
        self.0 &= !Self::bit(sig);
    }

    /// Tells if the set is empty.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The set without the signals of `other`.
    pub const fn without(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    /// The signal that the kernel gives first: a synchronous signal, else the lowest number.
    pub const fn next(self) -> Option<u32> {
        let sync = self.0 & SYNCHRONOUS.0;
        let set = if sync != 0 { sync } else { self.0 };
        if set == 0 { None } else { Some(set.trailing_zeros() + 1) }
    }
}

/// The action of a signal, in the layout of `struct sigaction` of the x86-64 kernel.
#[repr(C)]
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
pub struct SigAction {
    /// `SIG_DFL`, `SIG_IGN` or the address of the handler.
    pub handler: u64,
    /// The `SA_*` flags.
    pub flags: u64,
    /// The code that calls `rt_sigreturn` when the handler returns.
    pub restorer: u64,
    /// The signals that the handler blocks.
    pub mask: u64,
}

/// What the kernel does with a signal that has the action `SIG_DFL`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DefaultAction {
    /// The process ends.
    Terminate,
    /// The process ends with a core dump. rukernel does not write core files.
    CoreDump,
    /// The kernel discards the signal.
    Ignore,
    /// The process stops.
    Stop,
    /// A stopped process continues.
    Continue,
}

impl DefaultAction {
    /// Tells if the action ends the process.
    pub const fn is_fatal(self) -> bool {
        matches!(self, Self::Terminate | Self::CoreDump)
    }
}

/// The default action of `sig`, as the table in signal(7) gives it.
pub const fn default_action(sig: u32) -> DefaultAction {
    match sig {
        SIGCHLD | SIGURG | SIGWINCH => DefaultAction::Ignore,
        SIGCONT => DefaultAction::Continue,
        SIGSTOP | SIGTSTP | SIGTTIN | SIGTTOU => DefaultAction::Stop,
        SIGQUIT | SIGILL | SIGTRAP | SIGABRT | SIGBUS | SIGFPE | SIGSEGV | SIGXCPU | SIGXFSZ
        | SIGSYS => DefaultAction::CoreDump,
        _ => DefaultAction::Terminate,
    }
}

impl SigAction {
    /// Tells if the kernel discards `sig` with this action. `SIGCONT` with the default action
    /// continues a stopped process when it is sent, and then the kernel discards it.
    pub const fn ignores(&self, sig: u32) -> bool {
        match self.handler {
            SIG_IGN => true,
            SIG_DFL => {
                matches!(default_action(sig), DefaultAction::Ignore | DefaultAction::Continue)
            }
            _ => false,
        }
    }

    /// Tells if `sig` with this action stops the process.
    pub const fn is_stop(&self, sig: u32) -> bool {
        self.handler == SIG_DFL && matches!(default_action(sig), DefaultAction::Stop)
    }

    /// Tells if `sig` with this action ends the process.
    pub const fn is_fatal(&self, sig: u32) -> bool {
        self.handler == SIG_DFL && default_action(sig).is_fatal()
    }
}

/// The information about one signal. `to_bytes` gives the `siginfo_t` that the handler gets.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SigInfo {
    /// The signal number.
    pub signo: u32,
    /// The `si_code` value.
    pub code: i32,
    /// The `si_errno` value.
    pub errno: i32,
    /// The ID of the process that sent the signal, or of the child for `SIGCHLD`.
    pub pid: u32,
    /// The user ID of the sender.
    pub uid: u32,
    /// The exit code or the signal of the child, for `SIGCHLD`.
    pub status: i32,
    /// The address of the fault, for a signal that an exception caused. For `SIGSYS` from
    /// `seccomp`, the address of the system call. `status` is then the number of the system
    /// call, and `uid` is the architecture.
    pub addr: u64,
    /// The `si_value` that `sigqueue` or a timer gives.
    pub value: u64,
}

/// The size of `siginfo_t`.
pub const SIGINFO_SIZE: usize = 128;

impl SigInfo {
    /// The information of a signal from `kill`, `tkill` or the kernel.
    pub const fn new(signo: u32, code: i32, pid: u32) -> Self {
        Self { signo, code, errno: 0, pid, uid: 0, status: 0, addr: 0, value: 0 }
    }

    /// The information of a signal that an exception caused at `addr`.
    pub const fn fault(signo: u32, code: i32, addr: u64) -> Self {
        Self { signo, code, errno: 0, pid: 0, uid: 0, status: 0, addr, value: 0 }
    }

    /// Tells if the union of `siginfo_t` holds the fault address. Only the codes of the faults
    /// of each signal have this layout, as `siginfo_layout` of Linux tells. The code of a stop
    /// of `ptrace` is larger, and the union then holds the ID of the tracee.
    const fn is_fault(&self) -> bool {
        let limit = match self.signo {
            SIGILL => 11,
            SIGFPE => 15,
            SIGSEGV => 10,
            SIGBUS => 5,
            SIGTRAP => 6,
            _ => 0,
        };
        self.code > 0 && self.code <= limit
    }

    /// The information of `SIGSYS` from `seccomp`: the system call `nr` of the architecture
    /// `arch` at `ip`, with the data `errno` of the filter, as `force_sig_seccomp` of Linux gives
    /// it.
    pub const fn seccomp(nr: i32, arch: u32, ip: u64, errno: i32) -> Self {
        Self {
            signo: SIGSYS,
            code: SYS_SECCOMP,
            errno,
            pid: 0,
            uid: arch,
            status: nr,
            addr: ip,
            value: 0,
        }
    }

    /// Tells if the union of `siginfo_t` holds the system call of `seccomp`.
    const fn is_seccomp(&self) -> bool {
        self.signo == SIGSYS && self.code == SYS_SECCOMP
    }

    /// Tells if the union of `siginfo_t` holds the status of a child.
    const fn is_child(&self) -> bool {
        self.signo == SIGCHLD && self.code > 0
    }

    /// Reads the `siginfo_t` that a user program gave to `rt_sigqueueinfo`. It is the reverse of
    /// `to_bytes`.
    pub fn from_bytes(b: &[u8; SIGINFO_SIZE]) -> Self {
        let word = |off: usize| u32::from_ne_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]]);
        let mut long = [0u8; 8];
        long.copy_from_slice(&b[16..24]);
        let mut info = Self::new(word(0), word(8) as i32, 0);
        info.errno = word(4) as i32;
        if info.is_fault() {
            info.addr = u64::from_ne_bytes(long);
            return info;
        }
        if info.is_seccomp() {
            info.addr = u64::from_ne_bytes(long);
            info.status = word(24) as i32;
            info.uid = word(28);
            return info;
        }
        info.pid = word(16);
        info.uid = word(20);
        long.copy_from_slice(&b[24..32]);
        if info.is_child() {
            info.status = word(24) as i32;
        } else {
            info.value = u64::from_ne_bytes(long);
        }
        info
    }

    /// Gives the `siginfo_t` of the x86-64 ABI: `si_signo`, `si_errno` and `si_code` at 0, 4 and
    /// 8, and the union at 16. The union has `si_pid` and `si_uid` at 16 and 20, and then
    /// `si_status` or `si_value` at 24. For a fault, it has `si_addr` at 16. A timer puts its ID
    /// and its overrun count in the place of `si_pid` and `si_uid`.
    pub fn to_bytes(&self) -> [u8; SIGINFO_SIZE] {
        let mut b = [0u8; SIGINFO_SIZE];
        b[0..4].copy_from_slice(&self.signo.to_ne_bytes());
        b[4..8].copy_from_slice(&self.errno.to_ne_bytes());
        b[8..12].copy_from_slice(&self.code.to_ne_bytes());
        if self.is_fault() {
            b[16..24].copy_from_slice(&self.addr.to_ne_bytes());
        } else if self.is_seccomp() {
            b[16..24].copy_from_slice(&self.addr.to_ne_bytes());
            b[24..28].copy_from_slice(&self.status.to_ne_bytes());
            b[28..32].copy_from_slice(&self.uid.to_ne_bytes());
        } else {
            b[16..20].copy_from_slice(&self.pid.to_ne_bytes());
            b[20..24].copy_from_slice(&self.uid.to_ne_bytes());
            if self.is_child() {
                b[24..28].copy_from_slice(&self.status.to_ne_bytes());
            } else {
                b[24..32].copy_from_slice(&self.value.to_ne_bytes());
            }
        }
        b
    }
}

/// The most real time signals in one queue. Linux limits them with `RLIMIT_SIGPENDING`.
const MAX_QUEUED: usize = 1024;

/// The signals that wait for delivery. A standard signal is pending one time at most. A real
/// time signal can be in the queue more than one time.
#[derive(Clone, Debug, Default)]
pub struct Pending {
    set: SigSet,
    queue: VecDeque<SigInfo>,
}

impl Pending {
    /// An empty queue.
    pub const fn new() -> Self {
        Self { set: SigSet::EMPTY, queue: VecDeque::new() }
    }

    /// The pending signals.
    pub fn set(&self) -> SigSet {
        self.set
    }

    /// Adds a signal. Gives `false` if the kernel discards it: a standard signal that is pending
    /// already, or a real time signal when the queue is full.
    pub fn push(&mut self, info: SigInfo) -> bool {
        let sig = info.signo;
        if sig < SIGRTMIN && self.set.contains(sig) {
            return false;
        }
        if self.queue.len() >= MAX_QUEUED {
            return false;
        }
        self.set.add(sig);
        self.queue.push_back(info);
        true
    }

    /// Removes and gives the next signal that is not in `blocked`.
    pub fn take(&mut self, blocked: SigSet) -> Option<SigInfo> {
        let sig = self.set.without(blocked).next()?;
        let i = self.queue.iter().position(|i| i.signo == sig)?;
        let info = self.queue.remove(i)?;
        if !self.queue.iter().any(|i| i.signo == sig) {
            self.set.remove(sig);
        }
        Some(info)
    }

    /// Counts more overruns in the pending signal of the POSIX timer `id`, if there is one, and
    /// gives the new overrun count. A timer has one signal in the queue at most, as in Linux.
    pub fn add_overrun(&mut self, id: u32, overrun: u32) -> Option<i32> {
        let info = self.queue.iter_mut().find(|i| i.code == SI_TIMER && i.pid == id)?;
        info.uid = info.uid.saturating_add(overrun).min(i32::MAX as u32);
        Some(info.uid as i32)
    }

    /// Discards each instance of `sig`.
    pub fn discard(&mut self, sig: u32) {
        self.queue.retain(|i| i.signo != sig);
        self.set.remove(sig);
    }
}

/// `ss_flags` of `sigaltstack`: the thread runs on the stack.
pub const SS_ONSTACK: u32 = 1;
/// `ss_flags`: the stack is off.
pub const SS_DISABLE: u32 = 2;
/// `ss_flags`: the kernel turns the stack off while a handler runs on it.
pub const SS_AUTODISARM: u32 = 1 << 31;

/// The alternate signal stack of a thread.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AltStack {
    /// The lowest address of the stack.
    pub sp: u64,
    /// The size in bytes. A size of 0 means that the stack is off.
    pub size: u64,
    /// `SS_AUTODISARM` or 0.
    pub flags: u32,
}

impl AltStack {
    /// Tells if the stack pointer `rsp` is on the stack.
    pub const fn contains(&self, rsp: u64) -> bool {
        self.size != 0 && rsp > self.sp && rsp - self.sp <= self.size
    }

    /// The `ss_flags` value that `sigaltstack` gives when the stack pointer is `rsp`.
    pub const fn flags_at(&self, rsp: u64) -> u32 {
        if self.size == 0 {
            SS_DISABLE
        } else if self.contains(rsp) {
            SS_ONSTACK | self.flags
        } else {
            self.flags
        }
    }
}
