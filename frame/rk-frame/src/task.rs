//! Kernel tasks.
//!
//! A `Task` is a thread of the kernel: a kernel stack, the saved registers and a start function.
//! Each user thread runs in a task, which enters user mode with `UserContext::execute` and handles
//! the system calls of the thread. This is the model of OSTD, per spec/03-architecture.md.
//!
//! rk-frame does not choose which task runs next. A higher crate gives a `Scheduler` with
//! `inject_scheduler`, and rk-frame calls it when the current task yields, blocks or exits. The
//! scheduler of R1 is the round robin queue of rk-sched.
//!
//! The kernel runs with interrupts off, so a task in the kernel is not preempted. A task that runs
//! user code yields when `should_yield` tells that its time slice is over. In R1 there is one CPU.
//!
//! An interrupt handler takes no lock, so it cannot wake a task. The work that an interrupt starts
//! runs later as a bottom half, when the kernel is back from the interrupt and holds no lock: in
//! the idle loop of the scheduler, and after an interrupt in user mode. The bottom half wakes the
//! tasks whose timeout is over, and then calls each function of `add_bottom_half`.

use crate::arch::imp::task::{TaskContext, switch};
use crate::sync::{Once, SpinLock};
use alloc::alloc::{Layout, alloc, dealloc};
use alloc::boxed::Box;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::{Arc, Weak};
use core::any::Any;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};

/// The size of the kernel stack of a task.
pub const KERNEL_STACK_SIZE: usize = 32 * 1024;

/// The timer ticks that a task can run user code before `should_yield` tells it to yield.
pub const TIME_SLICE: u64 = 4;

/// The task is on the CPU.
const RUNNING: u8 = 0;
/// The task is in the queue of the scheduler.
const RUNNABLE: u8 = 1;
/// The task waits for a `wake`.
const BLOCKED: u8 = 2;
/// The task returned from its start function.
const EXITED: u8 = 3;

/// Chooses the next task to run.
pub trait Scheduler: Sync {
    /// Adds a task that can run.
    fn enqueue(&self, task: Arc<Task>);
    /// Removes the next task to run, if one can run.
    fn dequeue(&self) -> Option<Arc<Task>>;
}

static SCHEDULER: Once<&'static dyn Scheduler> = Once::new();

/// Gives the scheduler to rk-frame. Only the first call has an effect.
pub fn inject_scheduler(scheduler: &'static dyn Scheduler) {
    SCHEDULER.call_once(|| scheduler);
}

fn scheduler() -> &'static dyn Scheduler {
    *SCHEDULER.get().unwrap_or_else(|| panic!("no scheduler is injected"))
}

/// A kernel stack on the heap. A large heap block has an unmapped page before it and after it, so
/// an overflow is a page fault.
struct KernelStack {
    base: *mut u8,
}

// SAFETY: the stack is memory that only its task uses, through its stack pointer. The value only
// holds the address to give the memory back.
unsafe impl Send for KernelStack {}
// SAFETY: as above. No method reads or writes the memory through a shared reference.
unsafe impl Sync for KernelStack {}

const STACK_LAYOUT: Layout = match Layout::from_size_align(KERNEL_STACK_SIZE, 16) {
    Ok(layout) => layout,
    Err(_) => panic!("the stack layout is not valid"),
};

impl KernelStack {
    fn new() -> Option<Self> {
        // SAFETY: the layout has a size that is not zero.
        let base = unsafe { alloc(STACK_LAYOUT) };
        (!base.is_null()).then_some(Self { base })
    }

    fn top(&self) -> usize {
        self.base as usize + KERNEL_STACK_SIZE
    }
}

impl Drop for KernelStack {
    fn drop(&mut self) {
        // SAFETY: `alloc` gave `base` with this layout, and the task of the stack is not on the
        // CPU, because `finish_switch` drops an exited task only after the switch to another task.
        unsafe { dealloc(self.base, STACK_LAYOUT) };
    }
}

type Entry = Box<dyn FnOnce() + Send>;

/// A kernel task.
pub struct Task {
    id: u64,
    state: AtomicU8,
    /// The tick when the task last came on the CPU.
    start_tick: AtomicU64,
    context: UnsafeCell<TaskContext>,
    entry: SpinLock<Option<Entry>>,
    data: Box<dyn Any + Send + Sync>,
    /// `None` for the boot task, which runs on the boot stack.
    _stack: Option<KernelStack>,
}

// SAFETY: `context` is written only by `switch` on the CPU where the task stops, while interrupts
// are off and the task is not in a queue. It is read only by the switch that starts the task
// again. The other fields are atomic, locked or not changed after the task is made.
unsafe impl Sync for Task {}

impl core::fmt::Debug for Task {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Task").field("id", &self.id).finish_non_exhaustive()
    }
}

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// The task on the CPU, or `None` before the first call to `current`.
static CURRENT: SpinLock<Option<Arc<Task>>> = SpinLock::new(None);
/// An exited task that the next task drops after the switch, when its stack is not in use.
static EXITED_TASK: SpinLock<Option<Arc<Task>>> = SpinLock::new(None);

/// Makes a new task.
pub struct TaskOptions {
    entry: Entry,
    data: Box<dyn Any + Send + Sync>,
}

impl TaskOptions {
    /// Makes the options of a task that runs `entry`.
    pub fn new(entry: impl FnOnce() + Send + 'static) -> Self {
        Self { entry: Box::new(entry), data: Box::new(()) }
    }

    /// Sets the data of the task, for the higher crates. `Task::data` gives it.
    pub fn data(mut self, data: impl Any + Send + Sync) -> Self {
        self.data = Box::new(data);
        self
    }

    /// Makes the task and gives it to the scheduler. Gives `None` if no memory is free for the
    /// stack.
    pub fn spawn(self) -> Option<Arc<Task>> {
        let stack = KernelStack::new()?;
        let task = Arc::new(Task {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            state: AtomicU8::new(RUNNABLE),
            start_tick: AtomicU64::new(0),
            context: UnsafeCell::new(TaskContext::new(stack.top())),
            entry: SpinLock::new(Some(self.entry)),
            data: self.data,
            _stack: Some(stack),
        });
        scheduler().enqueue(task.clone());
        Some(task)
    }
}

impl Task {
    /// Gives the task on the CPU. The code that runs before the first task is the boot task.
    pub fn current() -> Arc<Task> {
        let mut current = CURRENT.lock();
        current
            .get_or_insert_with(|| {
                Arc::new(Task {
                    id: 0,
                    state: AtomicU8::new(RUNNING),
                    start_tick: AtomicU64::new(crate::time::ticks()),
                    context: UnsafeCell::new(TaskContext::default()),
                    entry: SpinLock::new(None),
                    data: Box::new(()),
                    _stack: None,
                })
            })
            .clone()
    }

    /// The number of the task. The boot task has the number 0.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// The data that `TaskOptions::data` gave.
    pub fn data(&self) -> &(dyn Any + Send + Sync) {
        &*self.data
    }

    /// Tells if the task returned from its start function.
    pub fn is_exited(&self) -> bool {
        self.state.load(Ordering::Acquire) == EXITED
    }

    /// Makes a blocked task runnable. Gives `false` if the task was not blocked.
    pub fn wake(self: &Arc<Self>) -> bool {
        let woken = self
            .state
            .compare_exchange(BLOCKED, RUNNABLE, Ordering::AcqRel, Ordering::Acquire)
            .is_ok();
        if woken {
            scheduler().enqueue(self.clone());
        }
        woken
    }
}

/// Tells if the current task ran for its time slice since it came on the CPU.
pub fn should_yield() -> bool {
    let start = Task::current().start_tick.load(Ordering::Relaxed);
    crate::time::ticks().wrapping_sub(start) >= TIME_SLICE
}

/// Lets the next task run. The current task stays runnable, so it runs again later.
pub fn yield_now() {
    let current = Task::current();
    current.state.store(RUNNABLE, Ordering::Release);
    scheduler().enqueue(current);
    schedule();
}

/// Stops the current task until a `wake`. Then the task runs again.
fn block() {
    schedule();
}

/// Ends the current task. Its stack goes back after the switch to the next task.
pub fn exit() -> ! {
    Task::current().state.store(EXITED, Ordering::Release);
    schedule();
    unreachable!("an exited task runs again")
}

/// Turns interrupts off while it lives, and then turns them back on if they were on.
struct IrqOff(bool);

impl IrqOff {
    fn new() -> Self {
        let on = crate::irq::enabled();
        crate::irq::disable();
        Self(on)
    }
}

impl Drop for IrqOff {
    fn drop(&mut self) {
        if self.0 {
            crate::irq::enable();
        }
    }
}

/// Switches to the next task from the scheduler. If no task can run, the CPU waits for an
/// interrupt. The current task is in the queue already if it can run.
fn schedule() {
    let _irq = IrqOff::new();
    let current = Task::current();
    let next = loop {
        if let Some(next) = scheduler().dequeue() {
            break next;
        }
        // No task can run. The bottom half of an interrupt can wake a task.
        crate::irq::wait();
        crate::irq::disable();
        run_bottom_half();
    };
    next.state.store(RUNNING, Ordering::Release);
    next.start_tick.store(crate::time::ticks(), Ordering::Relaxed);
    if Arc::ptr_eq(&current, &next) {
        return;
    }
    let from = current.context.get();
    let to = next.context.get().cast_const();
    *CURRENT.lock() = Some(next);
    if current.state.load(Ordering::Acquire) == EXITED {
        *EXITED_TASK.lock() = Some(current);
    } else {
        // The queue, a wait queue or a `wake` holds the current task, so its context lives.
        drop(current);
    }
    // SAFETY: interrupts are off. `to` is the context of `next`, which `CURRENT` holds, and it is
    // not on the CPU. `from` is the context of the current task, which `CURRENT` held until now
    // and which a queue, a wait queue or `EXITED_TASK` holds now.
    unsafe { switch(from, to) };
    finish_switch();
}

/// Drops the task that exited before the switch to this task.
fn finish_switch() {
    let exited = EXITED_TASK.lock().take();
    drop(exited);
}

/// The first code of a new task, on its own stack. `rk_task_entry` calls it.
pub(crate) extern "C" fn task_start() -> ! {
    finish_switch();
    let entry = Task::current().entry.lock().take();
    if let Some(entry) = entry {
        entry();
    }
    exit()
}

/// The tasks that wait with a timeout, by the tick of the timeout and the task number.
static TIMERS: SpinLock<BTreeMap<(u64, u64), Weak<Task>>> = SpinLock::new(BTreeMap::new());

/// The most functions that `add_bottom_half` keeps.
const MAX_BOTTOM_HALVES: usize = 4;

/// The functions of the bottom half.
static BOTTOM_HALVES: SpinLock<[Option<fn()>; MAX_BOTTOM_HALVES]> =
    SpinLock::new([None; MAX_BOTTOM_HALVES]);

/// Adds a function to the bottom half. A driver gives the function that takes the data of its
/// device, for a device that has no interrupt. The function runs with interrupts off and must not
/// block.
///
/// # Panics
///
/// Panics if the bottom half has `MAX_BOTTOM_HALVES` functions already.
pub fn add_bottom_half(f: fn()) {
    let mut halves = BOTTOM_HALVES.lock();
    let slot = halves.iter_mut().find(|h| h.is_none()).expect("too many bottom halves");
    *slot = Some(f);
}

/// Runs the bottom half: it wakes each task whose timeout is over, and then calls each function
/// of `add_bottom_half`.
pub(crate) fn run_bottom_half() {
    let now = crate::time::ticks();
    let expired = {
        let mut timers = TIMERS.lock();
        let later = timers.split_off(&(now + 1, 0));
        core::mem::replace(&mut *timers, later)
    };
    for task in expired.values().filter_map(Weak::upgrade) {
        task.wake();
    }
    let halves = *BOTTOM_HALVES.lock();
    for f in halves.into_iter().flatten() {
        f();
    }
}

/// A queue of tasks that wait for a condition.
pub struct WaitQueue {
    waiters: SpinLock<VecDeque<Arc<Task>>>,
}

impl WaitQueue {
    /// Makes an empty queue.
    pub const fn new() -> Self {
        Self { waiters: SpinLock::new(VecDeque::new()) }
    }

    /// Blocks the current task until `cond` gives a value, and gives the value. The task tests
    /// `cond` each time that it is woken.
    pub fn wait_until<R>(&self, mut cond: impl FnMut() -> Option<R>) -> R {
        loop {
            if let Some(value) = cond() {
                return value;
            }
            let current = Task::current();
            current.state.store(BLOCKED, Ordering::Release);
            self.waiters.lock().push_back(current.clone());
            // A wake that comes between the test and here finds the task in the queue.
            if let Some(value) = cond() {
                if current.state.swap(RUNNING, Ordering::AcqRel) == RUNNABLE {
                    // A wake made the task runnable and put it in the queue of the scheduler.
                    // The task runs again from there, so it lets the other tasks run first.
                    current.state.store(RUNNABLE, Ordering::Release);
                    schedule();
                } else {
                    self.waiters.lock().retain(|t| !Arc::ptr_eq(t, &current));
                }
                return value;
            }
            drop(current);
            block();
        }
    }

    /// Blocks the current task until `cond` gives a value or the tick count is at `deadline`, as
    /// `wait_until` blocks it. Gives `None` if the deadline comes first.
    pub fn wait_until_timeout<R>(
        &self,
        deadline: u64,
        mut cond: impl FnMut() -> Option<R>,
    ) -> Option<R> {
        let current = Task::current();
        let key = (deadline, current.id);
        TIMERS.lock().insert(key, Arc::downgrade(&current));
        drop(current);
        let value = self.wait_until(|| match cond() {
            Some(value) => Some(Some(value)),
            None if crate::time::ticks() >= deadline => Some(None),
            None => None,
        });
        TIMERS.lock().remove(&key);
        value
    }

    /// Wakes the first task that waits. Gives `false` if no task was woken.
    pub fn wake_one(&self) -> bool {
        loop {
            let Some(task) = self.waiters.lock().pop_front() else { return false };
            if task.wake() {
                return true;
            }
        }
    }

    /// Wakes each task that waits, and gives the number of tasks that it woke.
    pub fn wake_all(&self) -> usize {
        let waiters = core::mem::take(&mut *self.waiters.lock());
        waiters.into_iter().filter(|t| t.wake()).count()
    }
}

impl Default for WaitQueue {
    fn default() -> Self {
        Self::new()
    }
}
