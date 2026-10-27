//! The resource limits of a process, for `getrlimit`, `setrlimit` and `prlimit64`.
//!
//! Each process has a soft and a hard limit for each resource, and a child of `fork` gets a copy.
//! The kernel enforces few of them yet. The defaults are the defaults of Linux.

/// The number of resources. Linux names it `RLIM_NLIMITS`.
pub const RLIM_NLIMITS: usize = 16;
/// The size of a file that a process writes.
pub const RLIMIT_FSIZE: usize = 1;
/// The size of a core file.
pub const RLIMIT_CORE: usize = 4;
/// The size of the main stack.
pub const RLIMIT_STACK: usize = 3;
/// The number of processes of the user.
pub const RLIMIT_NPROC: usize = 6;
/// The number of open files.
pub const RLIMIT_NOFILE: usize = 7;
/// The bytes of memory that a process can lock.
pub const RLIMIT_MEMLOCK: usize = 8;
/// The default of `RLIMIT_MEMLOCK`, `MLOCK_LIMIT` of Linux: 8 MiB.
pub const MLOCK_LIMIT: u64 = 8 << 20;
/// The lowest nice value without `CAP_SYS_NICE`, as `20 - limit`.
pub const RLIMIT_NICE: usize = 13;
/// The highest real-time priority without `CAP_SYS_NICE`.
pub const RLIMIT_RTPRIO: usize = 14;
/// The value that tells that a resource has no limit.
pub const RLIM_INFINITY: u64 = u64::MAX;
/// The highest hard limit of `RLIMIT_NOFILE`. Linux names it `fs.nr_open`, and 1048576 is its
/// default.
pub const NR_OPEN: u64 = 1 << 20;

/// The soft and the hard limit of one resource.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limit {
    /// The soft limit, which the kernel enforces.
    pub cur: u64,
    /// The hard limit, the largest value of the soft limit.
    pub max: u64,
}

/// The limits of init. `stack` is the size of the main stack, `nproc` the largest PID and `nofile`
/// the size of a new descriptor table.
pub fn defaults(stack: u64, nproc: u64, nofile: u64) -> [Limit; RLIM_NLIMITS] {
    let mut limits = [Limit { cur: RLIM_INFINITY, max: RLIM_INFINITY }; RLIM_NLIMITS];
    limits[RLIMIT_STACK].cur = stack;
    limits[RLIMIT_NPROC] = Limit { cur: nproc, max: nproc };
    limits[RLIMIT_NOFILE] = Limit { cur: nofile, max: 4096 };
    // Linux writes no core file by default.
    limits[RLIMIT_CORE].cur = 0;
    limits[RLIMIT_MEMLOCK] = Limit { cur: MLOCK_LIMIT, max: MLOCK_LIMIT };
    limits[RLIMIT_NICE] = Limit { cur: 0, max: 0 };
    limits[RLIMIT_RTPRIO] = Limit { cur: 0, max: 0 };
    limits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_defaults_are_those_of_linux() {
        let l = defaults(8 << 20, 4_194_304, 1024);
        assert_eq!(l[RLIMIT_CORE], Limit { cur: 0, max: RLIM_INFINITY });
        assert_eq!(l[RLIMIT_NICE], Limit { cur: 0, max: 0 });
        assert_eq!(l[RLIMIT_MEMLOCK], Limit { cur: 8 << 20, max: 8 << 20 });
        assert_eq!(l[RLIMIT_STACK].cur, 8 << 20);
        assert_eq!(l[RLIMIT_NOFILE], Limit { cur: 1024, max: 4096 });
        assert_eq!(l[0].cur, RLIM_INFINITY);
    }
}
