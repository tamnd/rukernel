//! The `seccomp` state of a thread: the mode and the chain of filters.
//!
//! A filter attaches to the chain of the thread, and the new filter points to the chain that was
//! there before it. `fork` and `clone` give a copy of the chain to the new thread, and `execve`
//! keeps it. Each system call runs all the filters of the chain, and the action with the lowest
//! value wins. This is the model of kernel/seccomp.c of Linux.

use super::Thread;
use crate::bpf::{self, Insn, SECCOMP_DATA_SIZE};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;
use rk_abi::Errno;

/// The thread has no `seccomp` mode.
pub const SECCOMP_MODE_DISABLED: u32 = 0;
/// The thread can call only `read`, `write`, `exit` and `rt_sigreturn`.
pub const SECCOMP_MODE_STRICT: u32 = 1;
/// The filters of the thread check each system call.
pub const SECCOMP_MODE_FILTER: u32 = 2;

/// The action that ends the process with `SIGSYS`.
pub const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
/// The action that ends the thread with `SIGSYS`.
pub const SECCOMP_RET_KILL_THREAD: u32 = 0;
/// The action that sends `SIGSYS` to the thread. The call does not run.
pub const SECCOMP_RET_TRAP: u32 = 0x0003_0000;
/// The action that gives the error in the data. The call does not run.
pub const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
/// The action that sends a notification to the listener of the filter.
pub const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;
/// The action that stops the thread for its tracer.
pub const SECCOMP_RET_TRACE: u32 = 0x7ff0_0000;
/// The action that logs the call and runs it.
pub const SECCOMP_RET_LOG: u32 = 0x7ffc_0000;
/// The action that runs the call.
pub const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
/// The bits of the action in the return value of a filter.
pub const SECCOMP_RET_ACTION_FULL: u32 = 0xffff_0000;
/// The bits of the data in the return value of a filter.
pub const SECCOMP_RET_DATA: u32 = 0xffff;

/// The most instructions on one path of filters. Each filter adds 4 to the count, as in Linux.
const MAX_INSNS_PER_PATH: usize = (1 << 18) / bpf::INSN_SIZE;

/// One filter in a chain.
#[derive(Debug)]
pub struct Filter {
    /// The program, as the user gave it.
    prog: Vec<Insn>,
    /// `SECCOMP_FILTER_FLAG_LOG`: the kernel logs the actions of the filter.
    log: bool,
    /// The filter that was there before this one.
    prev: Option<Arc<Filter>>,
}

impl Filter {
    /// Makes a filter from a program. The caller checked the program with `bpf::check`.
    pub fn new(prog: Vec<Insn>, log: bool) -> Self {
        Self { prog, log, prev: None }
    }

    /// The program of the filter.
    pub fn prog(&self) -> &[Insn] {
        &self.prog
    }

    /// Tells if the filter has `SECCOMP_FILTER_FLAG_LOG`.
    pub fn log(&self) -> bool {
        self.log
    }

    /// The filter that was there before this one.
    pub fn prev(&self) -> Option<&Arc<Filter>> {
        self.prev.as_ref()
    }

    /// Tells if `self` comes after `other` in the chain, or is `other`.
    pub fn is_descendant_of(self: &Arc<Self>, other: &Arc<Filter>) -> bool {
        let mut f = Some(self);
        while let Some(cur) = f {
            if Arc::ptr_eq(cur, other) {
                return true;
            }
            f = cur.prev.as_ref();
        }
        false
    }
}

/// The value of an action for the comparison of two actions: the lowest wins.
const fn action_only(ret: u32) -> i32 {
    (ret & SECCOMP_RET_ACTION_FULL) as i32
}

/// The `seccomp` state of a thread.
#[derive(Clone, Debug, Default)]
pub struct Seccomp {
    /// The mode.
    pub mode: u32,
    /// The newest filter of the chain.
    pub filter: Option<Arc<Filter>>,
}

impl Thread {
    /// The `seccomp` mode of the thread.
    pub fn seccomp_mode(&self) -> u32 {
        self.seccomp_mode.load(Ordering::Acquire)
    }

    /// A copy of the `seccomp` state of the thread.
    pub fn seccomp(&self) -> Seccomp {
        self.seccomp.lock().clone()
    }

    /// Sets the `seccomp` state of the thread.
    pub fn set_seccomp(&self, state: Seccomp) {
        let mode = state.mode;
        *self.seccomp.lock() = state;
        self.seccomp_mode.store(mode, Ordering::Release);
    }

    /// Sets the strict mode.
    ///
    /// # Errors
    ///
    /// Gives `EINVAL` if the thread has filters.
    pub fn set_seccomp_strict(&self) -> Result<(), Errno> {
        let mut s = self.seccomp.lock();
        if s.mode != SECCOMP_MODE_DISABLED && s.mode != SECCOMP_MODE_STRICT {
            return Err(Errno::EINVAL);
        }
        s.mode = SECCOMP_MODE_STRICT;
        self.seccomp_mode.store(SECCOMP_MODE_STRICT, Ordering::Release);
        Ok(())
    }

    /// Adds `filter` to the chain of the thread, and sets the filter mode. Gives the new filter.
    ///
    /// # Errors
    ///
    /// Gives `EINVAL` if the thread is in the strict mode, and `ENOMEM` if the chain has too
    /// many instructions.
    pub fn attach_seccomp_filter(&self, mut filter: Filter) -> Result<Arc<Filter>, Errno> {
        let mut s = self.seccomp.lock();
        if s.mode != SECCOMP_MODE_DISABLED && s.mode != SECCOMP_MODE_FILTER {
            return Err(Errno::EINVAL);
        }
        let mut total = filter.prog.len();
        let mut walker = s.filter.as_ref();
        while let Some(f) = walker {
            total += f.prog.len() + 4;
            walker = f.prev.as_ref();
        }
        if total > MAX_INSNS_PER_PATH {
            return Err(Errno::ENOMEM);
        }
        filter.prev = s.filter.take();
        let filter = Arc::new(filter);
        s.filter = Some(filter.clone());
        s.mode = SECCOMP_MODE_FILTER;
        self.seccomp_mode.store(SECCOMP_MODE_FILTER, Ordering::Release);
        Ok(filter)
    }

    /// Gives the filter `n` of the thread, for `PTRACE_SECCOMP_GET_FILTER`. The oldest filter is
    /// 0.
    ///
    /// # Errors
    ///
    /// Gives `EINVAL` if the thread is not in the filter mode, and `ENOENT` if the filter `n` is
    /// not there.
    pub fn seccomp_filter(&self, n: u64) -> Result<Arc<Filter>, Errno> {
        let s = self.seccomp.lock();
        let Some(newest) = s.filter.as_ref().filter(|_| s.mode == SECCOMP_MODE_FILTER) else {
            return Err(Errno::EINVAL);
        };
        let mut chain = Vec::new();
        let mut f = Some(newest);
        while let Some(cur) = f {
            chain.push(cur);
            f = cur.prev.as_ref();
        }
        let n = usize::try_from(n).map_err(|_| Errno::ENOENT)?;
        if n >= chain.len() {
            return Err(Errno::ENOENT);
        }
        Ok(chain[chain.len() - 1 - n].clone())
    }

    /// The no_new_privs bit of the thread.
    pub fn no_new_privs(&self) -> bool {
        self.no_new_privs.load(Ordering::Acquire)
    }

    /// Sets the no_new_privs bit. Nothing clears it.
    pub fn set_no_new_privs(&self) {
        self.no_new_privs.store(true, Ordering::Release);
    }

    /// Gives the `seccomp` state and the no_new_privs bit of `parent` to the new thread, for
    /// `fork` and `clone`.
    pub(super) fn inherit_seccomp(&self, parent: &Thread) {
        self.set_seccomp(parent.seccomp());
        if parent.no_new_privs() {
            self.set_no_new_privs();
        }
    }
}

/// Runs each filter of the chain of `filter` on `data`. Gives the return value with the lowest
/// action, and the filter that gave it. For two filters with the same action, the newest filter
/// gives the data, as in Linux.
pub fn run_filters(filter: &Arc<Filter>, data: &[u8; SECCOMP_DATA_SIZE]) -> (u32, Arc<Filter>) {
    let mut ret = SECCOMP_RET_ALLOW;
    let mut matched = filter.clone();
    let mut f = Some(filter);
    while let Some(cur) = f {
        let r = bpf::run(&cur.prog, data);
        if action_only(r) < action_only(ret) {
            ret = r;
            matched = cur.clone();
        }
        f = cur.prev.as_ref();
    }
    (ret, matched)
}
