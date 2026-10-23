// rk-abigen generated this file from Linux 7.3, from <asm/signal.h>.
// Do not edit it. Change rk-abigen and run it again.

//! The signal numbers and the flags of `sigaction` and `sigaltstack`.

/// For blocking signals.
pub const SIG_BLOCK: u32 = 0;
/// `SA_NOCLDSTOP` from `<asm/signal.h>`.
pub const SA_NOCLDSTOP: u32 = 1;
/// `SIGHUP` from `<asm/signal.h>`.
pub const SIGHUP: u32 = 1;
/// For unblocking signals.
pub const SIG_UNBLOCK: u32 = 1;
/// `SA_NOCLDWAIT` from `<asm/signal.h>`.
pub const SA_NOCLDWAIT: u32 = 2;
/// `SIGINT` from `<asm/signal.h>`.
pub const SIGINT: u32 = 2;
/// For setting the signal mask.
pub const SIG_SETMASK: u32 = 2;
/// `SIGQUIT` from `<asm/signal.h>`.
pub const SIGQUIT: u32 = 3;
/// `SA_SIGINFO` from `<asm/signal.h>`.
pub const SA_SIGINFO: u32 = 4;
/// `SIGILL` from `<asm/signal.h>`.
pub const SIGILL: u32 = 4;
/// `SIGTRAP` from `<asm/signal.h>`.
pub const SIGTRAP: u32 = 5;
/// `SIGABRT` from `<asm/signal.h>`.
pub const SIGABRT: u32 = 6;
/// `SIGIOT` from `<asm/signal.h>`.
pub const SIGIOT: u32 = 6;
/// `SIGBUS` from `<asm/signal.h>`.
pub const SIGBUS: u32 = 7;
/// `SIGFPE` from `<asm/signal.h>`.
pub const SIGFPE: u32 = 8;
/// `SIGKILL` from `<asm/signal.h>`.
pub const SIGKILL: u32 = 9;
/// `SIGUSR1` from `<asm/signal.h>`.
pub const SIGUSR1: u32 = 10;
/// `SIGSEGV` from `<asm/signal.h>`.
pub const SIGSEGV: u32 = 11;
/// `SIGUSR2` from `<asm/signal.h>`.
pub const SIGUSR2: u32 = 12;
/// `SIGPIPE` from `<asm/signal.h>`.
pub const SIGPIPE: u32 = 13;
/// `SIGALRM` from `<asm/signal.h>`.
pub const SIGALRM: u32 = 14;
/// `SIGTERM` from `<asm/signal.h>`.
pub const SIGTERM: u32 = 15;
/// `SIGSTKFLT` from `<asm/signal.h>`.
pub const SIGSTKFLT: u32 = 16;
/// `SIGCHLD` from `<asm/signal.h>`.
pub const SIGCHLD: u32 = 17;
/// `SIGCONT` from `<asm/signal.h>`.
pub const SIGCONT: u32 = 18;
/// `SIGSTOP` from `<asm/signal.h>`.
pub const SIGSTOP: u32 = 19;
/// `SIGTSTP` from `<asm/signal.h>`.
pub const SIGTSTP: u32 = 20;
/// `SIGTTIN` from `<asm/signal.h>`.
pub const SIGTTIN: u32 = 21;
/// `SIGTTOU` from `<asm/signal.h>`.
pub const SIGTTOU: u32 = 22;
/// `SIGURG` from `<asm/signal.h>`.
pub const SIGURG: u32 = 23;
/// `SIGXCPU` from `<asm/signal.h>`.
pub const SIGXCPU: u32 = 24;
/// `SIGXFSZ` from `<asm/signal.h>`.
pub const SIGXFSZ: u32 = 25;
/// `SIGVTALRM` from `<asm/signal.h>`.
pub const SIGVTALRM: u32 = 26;
/// `SIGPROF` from `<asm/signal.h>`.
pub const SIGPROF: u32 = 27;
/// `SIGWINCH` from `<asm/signal.h>`.
pub const SIGWINCH: u32 = 28;
/// `SIGIO` from `<asm/signal.h>`.
pub const SIGIO: u32 = 29;
/// The same value as `SIGIO`.
pub const SIGPOLL: u32 = 29;
/// `SIGPWR` from `<asm/signal.h>`.
pub const SIGPWR: u32 = 30;
/// `SIGSYS` from `<asm/signal.h>`.
pub const SIGSYS: u32 = 31;
/// `SIGUNUSED` from `<asm/signal.h>`.
pub const SIGUNUSED: u32 = 31;
/// `SIGRTMIN` from `<asm/signal.h>`.
pub const SIGRTMIN: u32 = 32;
/// `SIGRTMAX` from `<asm/signal.h>`.
pub const SIGRTMAX: u32 = 64;
/// `SA_UNSUPPORTED` from `<asm/signal.h>`.
pub const SA_UNSUPPORTED: u32 = 0x400;
/// `SA_EXPOSE_TAGBITS` from `<asm/signal.h>`.
pub const SA_EXPOSE_TAGBITS: u32 = 0x800;
/// `MINSIGSTKSZ` from `<asm/signal.h>`.
pub const MINSIGSTKSZ: u32 = 0x1400;
/// `SIGSTKSZ` from `<asm/signal.h>`.
pub const SIGSTKSZ: u32 = 0x4000;
/// `SA_RESTORER` from `<asm/signal.h>`.
pub const SA_RESTORER: u32 = 0x400_0000;
/// `SA_ONSTACK` from `<asm/signal.h>`.
pub const SA_ONSTACK: u32 = 0x800_0000;
/// `SA_RESTART` from `<asm/signal.h>`.
pub const SA_RESTART: u32 = 0x1000_0000;
/// `SA_NODEFER` from `<asm/signal.h>`.
pub const SA_NODEFER: u32 = 0x4000_0000;
/// The same value as `SA_NODEFER`.
pub const SA_NOMASK: u32 = 0x4000_0000;
/// The same value as `SA_RESETHAND`.
pub const SA_ONESHOT: u32 = 0x8000_0000;
/// `SA_RESETHAND` from `<asm/signal.h>`.
pub const SA_RESETHAND: u32 = 0x8000_0000;
