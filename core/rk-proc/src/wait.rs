//! The status that `wait4` gives, and the children that it waits for.

use crate::signal::{CLD_CONTINUED, CLD_DUMPED, CLD_EXITED, CLD_KILLED, CLD_STOPPED};
use rk_abi::native::signal::SIGCONT;

/// The status of a child in the encoding of `wait4`. For a process that ended, it is the exit
/// code in bits 8 to 15, or the number of the signal that killed the process in bits 0 to 6 and
/// the core dump flag in bit 7. A stopped process has 0x7f in bits 0 to 7 and the stop signal in
/// bits 8 to 15, and a process that continued has 0xffff.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WaitStatus(pub i32);

impl WaitStatus {
    /// The status of a process that called `exit` with `code`. Only the low 8 bits stay.
    pub const fn exited(code: i32) -> Self {
        Self((code & 0xff) << 8)
    }

    /// The status of a process that the signal `sig` killed.
    pub const fn signaled(sig: u32, core: bool) -> Self {
        Self((sig & 0x7f) as i32 | if core { 0x80 } else { 0 })
    }

    /// The status of a process that the signal `sig` stopped.
    pub const fn stopped(sig: u32) -> Self {
        Self(((sig & 0xff) << 8) as i32 | 0x7f)
    }

    /// The status of a stopped process that `SIGCONT` continued.
    pub const CONTINUED: Self = Self(0xffff);

    /// The signal that stopped the process, if the status tells that it stopped.
    pub const fn stop_signal(self) -> Option<u32> {
        if self.0 & 0xff == 0x7f && self.0 != Self::CONTINUED.0 {
            Some(((self.0 >> 8) & 0xff) as u32)
        } else {
            None
        }
    }

    /// The `si_code` and the `si_status` of the `SIGCHLD` signal and of `waitid` for this
    /// status.
    pub const fn child_code(self) -> (i32, i32) {
        if self.0 == Self::CONTINUED.0 {
            return (CLD_CONTINUED, SIGCONT as i32);
        }
        if let Some(sig) = self.stop_signal() {
            return (CLD_STOPPED, sig as i32);
        }
        match self.signal() {
            Some(sig) if self.0 & 0x80 != 0 => (CLD_DUMPED, sig as i32),
            Some(sig) => (CLD_KILLED, sig as i32),
            None => (CLD_EXITED, (self.0 >> 8) & 0xff),
        }
    }

    /// The exit code, if the process called `exit`.
    pub const fn exit_code(self) -> Option<i32> {
        if self.0 & 0x7f == 0 { Some((self.0 >> 8) & 0xff) } else { None }
    }

    /// The number of the signal that killed the process, if a signal killed it.
    pub const fn signal(self) -> Option<u32> {
        let sig = self.0 & 0x7f;
        if sig != 0 && sig != 0x7f { Some(sig as u32) } else { None }
    }
}

/// The children that `wait4` waits for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaitTarget {
    /// Each child: `pid` is -1.
    Any,
    /// The child with this ID: `pid` is more than 0.
    Pid(u32),
    /// Each child in this process group: `pid` is 0 or less than -1.
    Pgid(u32),
}

/// The changes of the children that a wait takes, and what it does with them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WaitOptions {
    /// `WEXITED`: a child that ended.
    pub exited: bool,
    /// `WSTOPPED` or `WUNTRACED`: a child that a signal stopped.
    pub stopped: bool,
    /// `WCONTINUED`: a stopped child that `SIGCONT` continued.
    pub continued: bool,
    /// `WNOHANG`: the wait does not block.
    pub nohang: bool,
    /// `WNOWAIT`: the child stays, so a later wait can take it again.
    pub nowait: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_encoding() {
        let s = WaitStatus::exited(3);
        assert_eq!(s.0, 0x300);
        assert_eq!(s.exit_code(), Some(3));
        assert_eq!(s.signal(), None);
        assert_eq!(WaitStatus::exited(256).exit_code(), Some(0));
        let k = WaitStatus::signaled(9, false);
        assert_eq!(k.0, 9);
        assert_eq!(k.exit_code(), None);
        assert_eq!(k.signal(), Some(9));
        assert_eq!(WaitStatus::signaled(11, true).0, 0x8b);
        assert_eq!(WaitStatus::signaled(11, true).child_code(), (CLD_DUMPED, 11));
        assert_eq!(WaitStatus::exited(3).child_code(), (CLD_EXITED, 3));
        let st = WaitStatus::stopped(19);
        assert_eq!(st.0, 0x137f);
        assert_eq!((st.stop_signal(), st.signal(), st.exit_code()), (Some(19), None, None));
        assert_eq!(st.child_code(), (CLD_STOPPED, 19));
        let c = WaitStatus::CONTINUED;
        assert_eq!((c.stop_signal(), c.signal(), c.exit_code()), (None, None, None));
        assert_eq!(c.child_code(), (CLD_CONTINUED, SIGCONT as i32));
    }
}
