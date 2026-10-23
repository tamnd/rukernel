//! The status that `wait4` gives, and the children that it waits for.

/// The status of a process that ended, in the encoding of `wait4`: the exit code in bits 8 to 15,
/// or the number of the signal that killed the process in bits 0 to 6 and the core dump flag in
/// bit 7.
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
    }
}
