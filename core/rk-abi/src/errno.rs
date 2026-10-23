//! Linux error numbers.

/// A Linux error number.
///
/// Each fallible path in the kernel returns `Result<T, Errno>`, per spec/03-architecture.md. A
/// system call gives the negated number to user space. The value is always in `1..=4095`, because
/// Linux uses the top 4095 values of the return register for errors.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[repr(transparent)]
pub struct Errno(pub(crate) u16);

impl Errno {
    // rk-abigen generates the constants `Errno::EPERM` and the others in src/generated/errno.rs.

    /// The largest error number. Linux calls this value `MAX_ERRNO`.
    pub const MAX: u16 = 4095;

    /// Makes an error number. Gives `None` if the number is zero or larger than [`Errno::MAX`].
    pub const fn new(n: u16) -> Option<Self> {
        if n == 0 || n > Self::MAX { None } else { Some(Self(n)) }
    }

    /// Gives the error number.
    pub const fn get(self) -> u16 {
        self.0
    }

    /// Gives the value that a system call puts in the return register.
    pub const fn to_syscall_return(self) -> isize {
        -(self.0 as isize)
    }

    /// Reads a system call return value. Gives `None` if the value is not an error.
    pub const fn from_syscall_return(ret: isize) -> Option<Self> {
        if ret < 0 && ret >= -(Self::MAX as isize) { Some(Self((-ret) as u16)) } else { None }
    }
}

#[cfg(test)]
mod tests {
    use super::Errno;

    #[test]
    fn range() {
        assert_eq!(Errno::new(0), None);
        assert_eq!(Errno::new(4096), None);
        assert_eq!(Errno::new(38), Some(Errno::ENOSYS));
    }

    #[test]
    fn syscall_return_round_trip() {
        assert_eq!(Errno::ENOSYS.to_syscall_return(), -38);
        assert_eq!(Errno::from_syscall_return(-38), Some(Errno::ENOSYS));
        assert_eq!(Errno::from_syscall_return(-4096), None);
        assert_eq!(Errno::from_syscall_return(0), None);
        assert_eq!(Errno::from_syscall_return(7), None);
    }
}
