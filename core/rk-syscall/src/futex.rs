//! `futex`, the fast user space lock, as kernel/futex of Linux has it.
//!
//! A futex is a 32-bit word in user memory. User code changes the word with atomic instructions,
//! and calls `futex` only to wait for a change or to wake the tasks that wait. The kernel keeps a
//! queue of waiters for each key. The key of a private futex is the address space and the
//! address. The key of a futex in a shared area is the physical address, so that each process
//! that maps the page finds the same queue.
//!
//! The kernel runs one task at a time and a task in the kernel is not preempted. Thus the test of
//! the word and the insertion in the queue are atomic for each other task, as `FUTEX_WAIT` must
//! be. An SMP kernel will need a lock that the waker also takes.

use crate::cx::{Cx, SysResult};
use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};
use rk_abi::Errno;
use rk_abi::native::futex::{
    FUTEX_BITSET_MATCH_ANY, FUTEX_CLOCK_REALTIME, FUTEX_CMD_MASK, FUTEX_CMP_REQUEUE,
    FUTEX_OP_OPARG_SHIFT, FUTEX_PRIVATE_FLAG, FUTEX_REQUEUE, FUTEX_WAIT, FUTEX_WAIT_BITSET,
    FUTEX_WAKE, FUTEX_WAKE_BITSET, FUTEX_WAKE_OP,
};
use rk_abi::native::types::KernelTimespec;
use rk_frame::sync::SpinLock;
use rk_frame::task::WaitQueue;
use rk_frame::time::{HZ, ticks};
use rk_mm::AddressSpace;
use rk_proc::Thread;

const NSEC_PER_SEC: u64 = 1_000_000_000;

/// The key of a futex.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Key {
    /// The address space and the address of a private futex.
    Private(usize, usize),
    /// The physical address of a futex in a shared area.
    Shared(u64),
}

/// One task that waits on a futex.
struct Waiter {
    /// The bits of `FUTEX_WAIT_BITSET`. `FUTEX_WAIT` waits with each bit.
    bitset: u32,
    /// A wake sets this before it wakes the task.
    woken: AtomicBool,
    /// The task waits here alone.
    queue: WaitQueue,
}

/// The waiters of each key, in the order that they started to wait.
static FUTEXES: SpinLock<BTreeMap<Key, VecDeque<Arc<Waiter>>>> = SpinLock::new(BTreeMap::new());

/// Gives the key of the futex at `addr`. A futex without `FUTEX_PRIVATE_FLAG` in a shared area
/// gets a shared key.
fn key(vm: &Arc<AddressSpace>, addr: usize, private: bool) -> Result<Key, Errno> {
    if !addr.is_multiple_of(4) {
        return Err(Errno::EINVAL);
    }
    let private_key = Key::Private(Arc::as_ptr(vm) as usize, addr);
    if private {
        return Ok(private_key);
    }
    Ok(vm.shared_phys(addr)?.map_or(private_key, Key::Shared))
}

fn read_word(vm: &AddressSpace, addr: usize) -> Result<u32, Errno> {
    let mut b = [0u8; 4];
    vm.read(addr, &mut b)?;
    Ok(u32::from_ne_bytes(b))
}

/// Wakes at most `n` waiters of `key` that wait for a bit of `bitset`. Gives the number that it
/// woke.
fn wake_key(key: Key, n: u32, bitset: u32) -> u32 {
    let mut woken = alloc::vec::Vec::new();
    {
        let mut table = FUTEXES.lock();
        let Some(queue) = table.get_mut(&key) else { return 0 };
        let mut i = 0;
        while i < queue.len() && woken.len() < n as usize {
            if queue[i].bitset & bitset != 0 {
                woken.extend(queue.remove(i));
            } else {
                i += 1;
            }
        }
        if queue.is_empty() {
            table.remove(&key);
        }
    }
    for w in &woken {
        w.woken.store(true, Ordering::Release);
        w.queue.wake_all();
    }
    woken.len() as u32
}

/// Removes `waiter` from the table, if a wake did not remove it. A requeue can move a waiter, so
/// the search goes through each key.
fn remove_waiter(waiter: &Arc<Waiter>) {
    let mut table = FUTEXES.lock();
    let found = table.iter_mut().find_map(|(k, q)| {
        let i = q.iter().position(|w| Arc::ptr_eq(w, waiter))?;
        q.remove(i);
        Some((*k, q.is_empty()))
    });
    if let Some((k, true)) = found {
        table.remove(&k);
    }
}

/// Waits on the futex at `addr` while the word is `val`. `deadline` is a tick count.
fn wait(
    thread: &Thread,
    vm: &Arc<AddressSpace>,
    addr: usize,
    private: bool,
    val: u32,
    deadline: Option<u64>,
    bitset: u32,
) -> SysResult {
    let key = key(vm, addr, private)?;
    if read_word(vm, addr)? != val {
        return Err(Errno::EAGAIN);
    }
    let waiter =
        Arc::new(Waiter { bitset, woken: AtomicBool::new(false), queue: WaitQueue::new() });
    FUTEXES.lock().entry(key).or_default().push_back(waiter.clone());
    let cond = || {
        if waiter.woken.load(Ordering::Acquire) {
            Some(Ok(0))
        } else if thread.signal_pending() {
            // Linux starts a wait with a timeout again through `restart_syscall`. rukernel does
            // not have it yet, so that wait gives `EINTR`.
            Some(Err(if deadline.is_some() { Errno::EINTR } else { Errno::ERESTARTSYS }))
        } else {
            None
        }
    };
    let r = match deadline {
        Some(d) => waiter.queue.wait_until_timeout(d, cond).unwrap_or(Err(Errno::ETIMEDOUT)),
        None => waiter.queue.wait_until(cond),
    };
    if !waiter.woken.load(Ordering::Acquire) {
        remove_waiter(&waiter);
    }
    // A wake that came after the timeout or the signal still counts as a wake.
    if waiter.woken.load(Ordering::Acquire) { Ok(0) } else { r }
}

/// Reads the timeout of a wait and gives its deadline in ticks. `FUTEX_WAIT` has a relative
/// timeout. `FUTEX_WAIT_BITSET` has an absolute time of the clock, and the clocks of R1 both
/// count from boot.
fn deadline(cx: &Cx<'_>, addr: u64, absolute: bool) -> Result<Option<u64>, Errno> {
    if addr == 0 {
        return Ok(None);
    }
    let ts: KernelTimespec = cx.read_val(addr)?;
    if ts.tv_sec < 0 || !(0..NSEC_PER_SEC as i64).contains(&ts.tv_nsec) {
        return Err(Errno::EINVAL);
    }
    let ns = (ts.tv_sec as u64).saturating_mul(NSEC_PER_SEC).saturating_add(ts.tv_nsec as u64);
    let tick_ns = NSEC_PER_SEC / HZ;
    let ticks_from_boot = |ns: u64| ns.div_ceil(tick_ns);
    Ok(Some(if absolute {
        ticks_from_boot(ns)
    } else {
        ticks().saturating_add(ticks_from_boot(ns))
    }))
}

/// Does the operation of `FUTEX_WAKE_OP` on the word at `addr`, and gives the old value.
fn wake_op_update(vm: &AddressSpace, addr: usize, encoded: u32) -> Result<u32, Errno> {
    let mut op = (encoded >> 28) & 0xf;
    let sign_extend = |v: u32| ((v << 20) as i32 >> 20) as u32;
    let mut oparg = sign_extend((encoded >> 12) & 0xfff);
    if op & FUTEX_OP_OPARG_SHIFT != 0 {
        if oparg > 31 {
            return Err(Errno::EINVAL);
        }
        oparg = 1 << oparg;
        op &= !FUTEX_OP_OPARG_SHIFT;
    }
    let old = read_word(vm, addr)?;
    let new = match op {
        0 => oparg,
        1 => old.wrapping_add(oparg),
        2 => old | oparg,
        3 => old & !oparg,
        4 => old ^ oparg,
        _ => return Err(Errno::ENOSYS),
    };
    vm.write(addr, &new.to_ne_bytes())?;
    Ok(old)
}

/// Tells if the old value passes the compare of `FUTEX_WAKE_OP`.
fn wake_op_compare(old: u32, encoded: u32) -> Result<bool, Errno> {
    let cmp = (encoded >> 24) & 0xf;
    let arg = ((((encoded & 0xfff) << 20) as i32) >> 20) as i64;
    let old = i64::from(old as i32);
    Ok(match cmp {
        0 => old == arg,
        1 => old != arg,
        2 => old < arg,
        3 => old <= arg,
        4 => old > arg,
        5 => old >= arg,
        _ => return Err(Errno::ENOSYS),
    })
}

pub(crate) fn futex(
    cx: &Cx<'_>,
    uaddr: u64,
    op: u64,
    val: u64,
    utime: u64,
    uaddr2: u64,
    val3: u64,
) -> SysResult {
    let op = op as u32;
    let cmd = op & FUTEX_CMD_MASK & !FUTEX_PRIVATE_FLAG & !FUTEX_CLOCK_REALTIME;
    let private = op & FUTEX_PRIVATE_FLAG != 0;
    if op & FUTEX_CLOCK_REALTIME != 0 && !matches!(cmd, FUTEX_WAIT | FUTEX_WAIT_BITSET) {
        return Err(Errno::ENOSYS);
    }
    let (val, val3) = (val as u32, val3 as u32);
    let vm = cx.vm()?;
    let addr = uaddr as usize;
    match cmd {
        FUTEX_WAIT | FUTEX_WAIT_BITSET => {
            let bitset = if cmd == FUTEX_WAIT { FUTEX_BITSET_MATCH_ANY } else { val3 };
            if bitset == 0 {
                return Err(Errno::EINVAL);
            }
            let deadline = deadline(cx, utime, cmd == FUTEX_WAIT_BITSET)?;
            wait(cx.thread, &vm, addr, private, val, deadline, bitset)
        }
        FUTEX_WAKE | FUTEX_WAKE_BITSET => {
            let bitset = if cmd == FUTEX_WAKE { FUTEX_BITSET_MATCH_ANY } else { val3 };
            if bitset == 0 {
                return Err(Errno::EINVAL);
            }
            Ok(u64::from(wake_key(key(&vm, addr, private)?, val, bitset)))
        }
        FUTEX_REQUEUE | FUTEX_CMP_REQUEUE => {
            // The fourth argument is the most waiters to move, not a timeout.
            let n_requeue = utime as u32;
            if (val as i32) < 0 || (n_requeue as i32) < 0 {
                return Err(Errno::EINVAL);
            }
            let from = key(&vm, addr, private)?;
            let to = key(&vm, uaddr2 as usize, private)?;
            if cmd == FUTEX_CMP_REQUEUE && read_word(&vm, addr)? != val3 {
                return Err(Errno::EAGAIN);
            }
            let woken = wake_key(from, val, FUTEX_BITSET_MATCH_ANY);
            let mut table = FUTEXES.lock();
            let mut moved = VecDeque::new();
            if let Some(q) = table.get_mut(&from) {
                let n = (n_requeue as usize).min(q.len());
                moved.extend(q.drain(..n));
                if q.is_empty() {
                    table.remove(&from);
                }
            }
            let count = moved.len() as u32;
            if count > 0 {
                table.entry(to).or_default().extend(moved);
            }
            Ok(u64::from(woken + count))
        }
        FUTEX_WAKE_OP => {
            let n2 = utime as u32;
            let k1 = key(&vm, addr, private)?;
            let k2 = key(&vm, uaddr2 as usize, private)?;
            if !uaddr2.is_multiple_of(4) {
                return Err(Errno::EINVAL);
            }
            let old = wake_op_update(&vm, uaddr2 as usize, val3)?;
            let mut woken = wake_key(k1, val, FUTEX_BITSET_MATCH_ANY);
            if wake_op_compare(old, val3)? {
                woken += wake_key(k2, n2, FUTEX_BITSET_MATCH_ANY);
            }
            Ok(u64::from(woken))
        }
        // The priority inheritance operations and `FUTEX_FD` are not in R1.
        _ => Err(Errno::ENOSYS),
    }
}

/// Clears the word of `clear_child_tid` and wakes one waiter when a thread ends, as `mm_release`
/// of Linux does. `pthread_join` waits on this word.
pub(crate) fn exit_clear_tid(thread: &Thread) {
    let addr = thread.clear_child_tid();
    if addr == 0 {
        return;
    }
    let Some(vm) = thread.process().vm() else { return };
    if vm.write(addr, &0u32.to_ne_bytes()).is_ok()
        && let Ok(k) = key(&vm, addr, false)
    {
        wake_key(k, 1, FUTEX_BITSET_MATCH_ANY);
    }
}
