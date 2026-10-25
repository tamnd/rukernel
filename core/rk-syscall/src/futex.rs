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
//! be. The same is true for the read and the write of the word in the priority inheritance
//! operations. An SMP kernel will need a lock that the waker also takes, and a compare and
//! exchange on the word.
//!
//! The priority inheritance operations give the lock protocol of Linux. They do not change the
//! priority of the owner, because the scheduler of R1 has no priorities.
//!
//! At the exit of a thread, the kernel walks the robust list of the thread. It marks each futex
//! that the thread holds with `FUTEX_OWNER_DIED`, and wakes one waiter, as `exit_robust_list` of
//! Linux does.

use crate::cx::{Cx, SysResult};
use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};
use rk_abi::Errno;
use rk_abi::native::futex::{
    FUTEX_BITSET_MATCH_ANY, FUTEX_CLOCK_REALTIME, FUTEX_CMD_MASK, FUTEX_CMP_REQUEUE, FUTEX_LOCK_PI,
    FUTEX_LOCK_PI2, FUTEX_OP_OPARG_SHIFT, FUTEX_OWNER_DIED, FUTEX_PRIVATE_FLAG, FUTEX_REQUEUE,
    FUTEX_TID_MASK, FUTEX_TRYLOCK_PI, FUTEX_UNLOCK_PI, FUTEX_WAIT, FUTEX_WAIT_BITSET,
    FUTEX_WAITERS, FUTEX_WAKE, FUTEX_WAKE_BITSET, FUTEX_WAKE_OP, ROBUST_LIST_LIMIT,
};
use rk_abi::native::time::{CLOCK_MONOTONIC, CLOCK_REALTIME};
use rk_abi::native::types::{KernelTimespec, RobustListHead};
use rk_frame::sync::SpinLock;
use rk_frame::task::WaitQueue;
use rk_frame::time::HZ;
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
    /// The thread ID of the task, for the priority inheritance operations.
    tid: u32,
    /// A wake sets this before it wakes the task.
    woken: AtomicBool,
    /// `FUTEX_UNLOCK_PI` sets this when it gives the lock to the task.
    owner: AtomicBool,
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

/// Writes `new` to the word at `addr` if it has the value `old`. Gives `false` if the word has
/// another value. User code on another CPU can change the word at any time, so the kernel does
/// not write a word that it read before without this check.
fn replace_word(vm: &AddressSpace, addr: usize, old: u32, new: u32) -> Result<bool, Errno> {
    Ok(vm.compare_exchange_u32(addr, old, new)? == old)
}

impl Waiter {
    fn new(tid: u32, bitset: u32) -> Arc<Self> {
        Arc::new(Self {
            tid,
            bitset,
            woken: AtomicBool::new(false),
            owner: AtomicBool::new(false),
            queue: WaitQueue::new(),
        })
    }
}

/// Tells if a task waits on `key`.
fn has_waiters(key: Key) -> bool {
    FUTEXES.lock().get(&key).is_some_and(|q| !q.is_empty())
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

/// Puts `waiter` in the queue of `key` and waits for a wake. `deadline` is a tick count. A signal
/// gives `on_signal`. Gives `Ok` if a wake came, also after the timeout or the signal.
fn sleep(
    thread: &Thread,
    key: Key,
    waiter: &Arc<Waiter>,
    deadline: Option<u64>,
    on_signal: Errno,
) -> Result<(), Errno> {
    FUTEXES.lock().entry(key).or_default().push_back(waiter.clone());
    let cond = || {
        if waiter.woken.load(Ordering::Acquire) {
            Some(Ok(()))
        } else if thread.signal_pending() {
            Some(Err(on_signal))
        } else {
            None
        }
    };
    let r = match deadline {
        Some(d) => waiter.queue.wait_until_timeout(d, cond).unwrap_or(Err(Errno::ETIMEDOUT)),
        None => waiter.queue.wait_until(cond),
    };
    if !waiter.woken.load(Ordering::Acquire) {
        remove_waiter(waiter);
    }
    if waiter.woken.load(Ordering::Acquire) { Ok(()) } else { r }
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
    // Linux starts a wait with a timeout again through `restart_syscall`. rukernel does not have
    // it yet, so that wait gives `EINTR`.
    let on_signal = if deadline.is_some() { Errno::EINTR } else { Errno::ERESTARTSYS };
    sleep(thread, key, &Waiter::new(thread.tid(), bitset), deadline, on_signal)?;
    Ok(0)
}

/// Takes the priority inheritance futex at `addr` for `thread`, as `futex_lock_pi` of Linux does.
/// The word has the thread ID of the owner. A task that waits sets `FUTEX_WAITERS`, so that the
/// owner calls `FUTEX_UNLOCK_PI`. With `trylock`, a futex that has an owner gives `EAGAIN`.
fn lock_pi(
    thread: &Thread,
    vm: &Arc<AddressSpace>,
    addr: usize,
    private: bool,
    deadline: Option<u64>,
    trylock: bool,
) -> SysResult {
    let key = key(vm, addr, private)?;
    let tid = thread.tid();
    loop {
        let word = read_word(vm, addr)?;
        let owner = word & FUTEX_TID_MASK;
        if owner == tid {
            return Err(Errno::EDEADLK);
        }
        if owner == 0 {
            // The futex of a dead owner keeps `FUTEX_OWNER_DIED`, so that the new owner sees it.
            let waiters = if has_waiters(key) { FUTEX_WAITERS } else { 0 };
            if !replace_word(vm, addr, word, tid | (word & FUTEX_OWNER_DIED) | waiters)? {
                continue;
            }
            return Ok(0);
        }
        if trylock {
            return Err(Errno::EAGAIN);
        }
        if rk_proc::find_thread(owner).is_none() {
            return Err(Errno::ESRCH);
        }
        if word & FUTEX_WAITERS == 0 && !replace_word(vm, addr, word, word | FUTEX_WAITERS)? {
            continue;
        }
        let waiter = Waiter::new(tid, FUTEX_BITSET_MATCH_ANY);
        sleep(thread, key, &waiter, deadline, Errno::ERESTARTNOINTR)?;
        if waiter.owner.load(Ordering::Acquire) {
            return Ok(0);
        }
    }
}

/// Releases the priority inheritance futex at `addr`, as `futex_unlock_pi` of Linux does. The
/// first task that waits becomes the owner.
fn unlock_pi(thread: &Thread, vm: &Arc<AddressSpace>, addr: usize, private: bool) -> SysResult {
    let key = key(vm, addr, private)?;
    let word = read_word(vm, addr)?;
    if word & FUTEX_TID_MASK != thread.tid() {
        return Err(Errno::EPERM);
    }
    let next = {
        let mut table = FUTEXES.lock();
        let next = table.get_mut(&key).and_then(VecDeque::pop_front);
        let more = table.get(&key).is_some_and(|q| !q.is_empty());
        if table.get(&key).is_some_and(VecDeque::is_empty) {
            table.remove(&key);
        }
        next.map(|w| (w, more))
    };
    // Only the owner changes the word while it has an owner, and the owner is this thread, so
    // the word cannot change. The check is for a word that user code wrote in a wrong way.
    let Some((next, more)) = next else {
        replace_word(vm, addr, word, 0)?;
        return Ok(0);
    };
    let waiters = if more { FUTEX_WAITERS } else { 0 };
    replace_word(vm, addr, word, next.tid | waiters)?;
    next.owner.store(true, Ordering::Release);
    next.woken.store(true, Ordering::Release);
    next.queue.wake_all();
    Ok(0)
}

/// Reads the timeout of a wait and gives its deadline in ticks. `FUTEX_WAIT` has a relative
/// timeout, and `absolute` is `None`. The other waits have an absolute time of the clock that
/// `absolute` gives.
fn deadline(cx: &Cx<'_>, addr: u64, absolute: Option<u32>) -> Result<Option<u64>, Errno> {
    if addr == 0 {
        return Ok(None);
    }
    let ts: KernelTimespec = cx.read_val(addr)?;
    if ts.tv_sec < 0 || !(0..NSEC_PER_SEC as i64).contains(&ts.tv_nsec) {
        return Err(Errno::EINVAL);
    }
    let ns = (ts.tv_sec as u64).saturating_mul(NSEC_PER_SEC).saturating_add(ts.tv_nsec as u64);
    Ok(Some(if let Some(clock) = absolute {
        crate::info::boot_ns(clock, ns).div_ceil(NSEC_PER_SEC / HZ)
    } else {
        crate::info::deadline_after(ns)
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
    if op > 4 {
        return Err(Errno::ENOSYS);
    }
    loop {
        let old = read_word(vm, addr)?;
        let new = match op {
            0 => oparg,
            1 => old.wrapping_add(oparg),
            2 => old | oparg,
            3 => old & !oparg,
            _ => old ^ oparg,
        };
        if replace_word(vm, addr, old, new)? {
            return Ok(old);
        }
    }
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
    let clock = if op & FUTEX_CLOCK_REALTIME != 0 { CLOCK_REALTIME } else { CLOCK_MONOTONIC };
    let private = op & FUTEX_PRIVATE_FLAG != 0;
    if op & FUTEX_CLOCK_REALTIME != 0 && !matches!(cmd, FUTEX_WAIT_BITSET | FUTEX_LOCK_PI2) {
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
            let deadline = deadline(cx, utime, (cmd == FUTEX_WAIT_BITSET).then_some(clock))?;
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
        // The timeout of `FUTEX_LOCK_PI` and `FUTEX_LOCK_PI2` is an absolute time. The clock of
        // `FUTEX_LOCK_PI` is always `CLOCK_REALTIME`.
        FUTEX_LOCK_PI | FUTEX_LOCK_PI2 => {
            let clock = if cmd == FUTEX_LOCK_PI { CLOCK_REALTIME } else { clock };
            let deadline = deadline(cx, utime, Some(clock))?;
            lock_pi(cx.thread, &vm, addr, private, deadline, false)
        }
        FUTEX_TRYLOCK_PI => lock_pi(cx.thread, &vm, addr, private, None, true),
        FUTEX_UNLOCK_PI => unlock_pi(cx.thread, &vm, addr, private),
        // The requeue to a priority inheritance futex and `FUTEX_FD` are not in R2. glibc and
        // musl do not use them.
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

/// Marks the futex at `addr` that the dead thread `tid` holds, as `handle_futex_death` of Linux
/// does. `pending` tells that the address is the `list_op_pending` of the list.
fn futex_death(vm: &Arc<AddressSpace>, addr: usize, tid: u32, pi: bool, pending: bool) {
    // A user thread on another CPU can change the word, so the change is a compare and exchange.
    let word = loop {
        let Ok(word) = read_word(vm, addr) else { return };
        if word & FUTEX_TID_MASK != tid {
            break word;
        }
        match replace_word(vm, addr, word, (word & FUTEX_WAITERS) | FUTEX_OWNER_DIED) {
            Ok(true) => break word,
            Ok(false) => {}
            Err(_) => return,
        }
    };
    let owner = word & FUTEX_TID_MASK;
    // The thread released the futex, but it did not wake a waiter before it died.
    let wake =
        if pending && !pi && owner == 0 { true } else { owner == tid && word & FUTEX_WAITERS != 0 };
    if wake && let Ok(k) = key(vm, addr, false) {
        wake_key(k, 1, FUTEX_BITSET_MATCH_ANY);
    }
}

/// Walks the robust list of `thread` when it exits or calls `execve`, as `exit_robust_list` of
/// Linux does. Each entry of the list is in a lock that the thread holds. Bit 0 of an entry tells
/// that the lock is a priority inheritance futex. A list that is not correct stops the walk.
pub(crate) fn exit_robust_list(thread: &Thread) {
    let head = thread.robust_list();
    if head == 0 {
        return;
    }
    thread.set_robust_list(0);
    let Some(vm) = thread.process().vm() else { return };
    let read_u64 = |addr: usize| {
        let mut b = [0u8; 8];
        vm.read(addr, &mut b).ok().map(|()| u64::from_ne_bytes(b) as usize)
    };
    let mut b = [0u8; size_of::<RobustListHead>()];
    if vm.read(head, &mut b).is_err() {
        return;
    }
    let Ok(h) = <RobustListHead as zerocopy::FromBytes>::read_from_bytes(&b) else { return };
    let offset = h.futex_offset as isize;
    let pending = h.list_op_pending as usize;
    let futex_addr = |entry: usize| (entry & !1).wrapping_add_signed(offset);
    let tid = thread.tid();
    let mut entry = h.list.next as usize;
    for _ in 0..ROBUST_LIST_LIMIT {
        if entry & !1 == head {
            break;
        }
        // Read the next entry first, because the futex can be in the same memory.
        let Some(next) = read_u64(entry & !1) else { break };
        if entry != pending {
            futex_death(&vm, futex_addr(entry), tid, entry & 1 != 0, false);
        }
        entry = next;
    }
    if pending != 0 {
        futex_death(&vm, futex_addr(pending), tid, pending & 1 != 0, true);
    }
}

pub(crate) fn set_robust_list(cx: &Cx<'_>, head: u64, len: u64) -> SysResult {
    if len != size_of::<RobustListHead>() as u64 {
        return Err(Errno::EINVAL);
    }
    cx.thread.set_robust_list(head as usize);
    Ok(0)
}

/// Gives the robust list of the thread `tid`, or of the caller for 0.
pub(crate) fn get_robust_list(cx: &Cx<'_>, tid: u64, head: u64, len: u64) -> SysResult {
    let head_addr = match tid as u32 {
        0 => cx.thread.robust_list(),
        tid => rk_proc::find_thread(tid).ok_or(Errno::ESRCH)?.robust_list(),
    };
    cx.write_val(head, &(head_addr as u64))?;
    cx.write_val(len, &(size_of::<RobustListHead>() as u64))?;
    Ok(0)
}
