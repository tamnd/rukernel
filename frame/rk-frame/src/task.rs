//! Kernel tasks.
//!
//! A `Task` is a thread of the kernel: a kernel stack, the saved registers and a start function.
//! Each user thread runs in a task, which enters user mode with `UserContext::execute` and handles
//! the system calls of the thread. This is the model of OSTD, per spec/03-architecture.md.
//!
//! rk-frame does not choose which task runs next. A higher crate gives a `Scheduler` with
//! `inject_scheduler`, and rk-frame calls it when the current task yields, blocks or exits. The
//! scheduler is the fair class of rk-sched.
//!
//! The kernel runs with interrupts off, so a task in the kernel is not preempted. A task that runs
//! user code yields when `should_yield` tells that its time slice is over.
//!
//! Each CPU runs user code at the same time, but only one CPU at a time runs kernel code. A CPU
//! holds the kernel lock while it runs kernel code, and releases it when it enters user mode or
//! waits for an interrupt. This is the big kernel lock of Linux 2.0, and it keeps the code of the
//! kernel, which was written for one CPU, correct. The scheduler can keep a queue for each CPU, and
//! tells which CPU gets a task that becomes runnable. Each CPU has its own current task, and an
//! idle task that runs when no other task can run.
//!
//! An interrupt handler takes no lock, so it cannot wake a task. The work that an interrupt starts
//! runs later as a bottom half, when the kernel is back from the interrupt and holds no lock: in
//! the idle loop of the scheduler, and after an interrupt in user mode. The bottom half wakes the
//! tasks whose timeout is over, and then calls each function of `add_bottom_half`.

use crate::arch::imp::cpu::{self, MAX_CPUS};
use crate::arch::imp::smp;
use crate::arch::imp::task::{TaskContext, switch};
use crate::sync::{Once, SpinLock};
use alloc::alloc::{Layout, alloc, dealloc};
use alloc::boxed::Box;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::{Arc, Weak};
use core::any::Any;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};

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
/// The task is the idle task of a CPU. It is never in the queue of the scheduler.
const IDLE: u8 = 4;

/// Why a task goes into the queue of the scheduler.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Enqueue {
    /// The task is new.
    New,
    /// The task was blocked, and a `wake` made it runnable.
    Wake,
    /// The task gave the CPU, and it can run again.
    Yield,
}

/// Chooses the next task to run.
///
/// rk-frame calls `put_prev` when the current task stops on the CPU, and `set_next` when a task
/// comes on the CPU. A yield calls `put_prev` before `enqueue`. The scheduler keeps its values for
/// each task in the data that `new_data` makes, and `Task::sched_data` gives them. The scheduler
/// can keep a queue for each CPU. `dequeue` then takes a task from the queue of the CPU that calls
/// it.
pub trait Scheduler: Sync {
    /// Makes the data of the scheduler for a new task.
    fn new_data(&self) -> Box<dyn Any + Send + Sync> {
        Box::new(())
    }
    /// Adds a task that can run. Gives the CPU whose queue has the task now, so that rk-frame
    /// wakes that CPU if it is idle.
    fn enqueue(&self, task: Arc<Task>, why: Enqueue) -> usize;
    /// Removes the next task to run, if one can run.
    fn dequeue(&self) -> Option<Arc<Task>>;
    /// The current task stops on the CPU. `sleeping` is true if the task blocked or exited.
    fn put_prev(&self, _task: &Task, _sleeping: bool) {}
    /// The task comes on the CPU.
    fn set_next(&self, _task: &Task) {}
    /// Tells if the current task `task` would run again at once after a yield, because no other
    /// task waits for this CPU and the task can stay on it. `yield_now` then returns at once, as
    /// `yield_task_fair` of Linux does when the queue has only the current task.
    fn runs_alone(&self, _task: &Task) -> bool {
        false
    }
    /// Tells if the current task must give the CPU to another task. `ran` is the count of timer
    /// ticks since the task came on the CPU.
    fn should_yield(&self, _task: &Task, ran: u64) -> bool {
        ran >= TIME_SLICE
    }
    /// Sets the share of the CPU of the task from the nice value `nice`. If `idle` is true, the
    /// task has the smallest share, as the `SCHED_IDLE` policy of Linux gives.
    fn set_nice(&self, _task: &Task, _nice: i32, _idle: bool) {}
    /// Sets the CPUs that the task can use, one bit for each CPU, as `sched_setaffinity` of
    /// Linux. If the task moves to the queue of another CPU, gives that CPU.
    fn set_affinity(&self, _task: &Task, _mask: u64) -> Option<usize> {
        None
    }
    /// Puts the task in the group `group`, the cgroup of its thread. The scheduler charges the
    /// run time of the task to the group, and the group can change the share of the task.
    fn set_group(&self, _task: &Task, _group: u32) {}
}

static SCHEDULER: Once<&'static dyn Scheduler> = Once::new();

/// Gives the scheduler to rk-frame. Only the first call has an effect.
pub fn inject_scheduler(scheduler: &'static dyn Scheduler) {
    SCHEDULER.call_once(|| scheduler);
}

fn scheduler() -> &'static dyn Scheduler {
    *SCHEDULER.get().unwrap_or_else(|| panic!("no scheduler is injected"))
}

/// A kernel stack on the heap. A large heap block that is not in the direct map has an unmapped
/// page before it and after it, so an overflow is a page fault.
struct KernelStack {
    base: *mut u8,
}

// SAFETY: the stack is memory that only its task uses, through its stack pointer. The value only
// holds the address to give the memory back.
unsafe impl Send for KernelStack {}
// SAFETY: as above. No method reads or writes the memory through a shared reference.
unsafe impl Sync for KernelStack {}

// A kernel stack must not come from the direct map, where it has no guard page.
const _: () = assert!(KERNEL_STACK_SIZE > crate::mm::heap::DIRECT_PAGES * crate::addr::PAGE_SIZE);

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
    /// The clock in nanoseconds when the task last came on the CPU.
    run_start: AtomicU64,
    /// The nanoseconds on the CPU of the runs of the task that ended.
    cpu_ns: AtomicU64,
    /// The tick of the last call to `Scheduler::should_yield` for the task, or `u64::MAX`.
    yield_tick: AtomicU64,
    /// A change of the task asks for a call to `Scheduler::should_yield` before the next tick.
    resched: AtomicBool,
    context: UnsafeCell<TaskContext>,
    entry: SpinLock<Option<Entry>>,
    data: Box<dyn Any + Send + Sync>,
    /// The data of the scheduler, which `Scheduler::new_data` makes at the first use.
    sched: Once<Box<dyn Any + Send + Sync>>,
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

/// The tasks of one CPU.
struct PerCpu {
    /// The task on the CPU, or `None` before the first call to `current`.
    current: SpinLock<Option<Arc<Task>>>,
    /// The task that runs when no other task can run.
    idle: Once<Arc<Task>>,
    /// The scheduler asks the task on the CPU to call `Scheduler::should_yield` before the next
    /// tick, as `TIF_NEED_RESCHED` of Linux.
    resched: AtomicBool,
}

static CPUS: [PerCpu; MAX_CPUS] = [const {
    PerCpu { current: SpinLock::new(None), idle: Once::new(), resched: AtomicBool::new(false) }
}; MAX_CPUS];

fn this_cpu() -> &'static PerCpu {
    &CPUS[cpu::id()]
}

/// The kernel lock. The boot CPU holds it from the start.
static KERNEL_LOCK: AtomicBool = AtomicBool::new(true);

/// The CPUs that wait for an interrupt in `kernel_lock`.
static LOCK_WAITERS: AtomicU64 = AtomicU64::new(0);

/// The tries of `kernel_lock` before the CPU waits for an interrupt. A short spin takes a lock
/// that is free again soon without an interrupt. On TCG with 4 CPUs on a busy host, hackbench took
/// 235 s with a spin only, 123 s with 4096 tries and 70 s with 64 tries (#396).
const LOCK_SPINS: u32 = 1 << 6;

/// Takes the kernel lock. While the CPU waits, it does the TLB requests of the other CPUs, because
/// the CPU that holds the lock can wait for them.
///
/// After `LOCK_SPINS` tries, the CPU waits for an interrupt, and `kernel_unlock` sends one. In a
/// virtual machine, a spin uses a CPU of the host. When the host has fewer free CPUs than the
/// machine, for example on a busy host, the spin of a CPU can stop the host from running the CPU
/// that holds the lock, and the kernel becomes very slow. The callers hold no lock and no state,
/// as the idle loop, so the interrupt handlers can run during the wait.
pub(crate) fn kernel_lock() {
    let mut tries = 0;
    while KERNEL_LOCK
        .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        smp::poll();
        if tries < LOCK_SPINS {
            tries += 1;
            core::hint::spin_loop();
            continue;
        }
        let bit = 1u64 << cpu::id();
        // The order of the bit and the test is the order of the release and the test of
        // `kernel_unlock`, so one of the two CPUs sees the other.
        LOCK_WAITERS.fetch_or(bit, Ordering::SeqCst);
        if KERNEL_LOCK.load(Ordering::SeqCst) {
            let enabled = crate::irq::enabled();
            // An interrupt that comes before `wait` stays pending, and `wait` takes it.
            crate::irq::wait();
            if !enabled {
                crate::irq::disable();
            }
        }
        LOCK_WAITERS.fetch_and(!bit, Ordering::SeqCst);
    }
}

/// Releases the kernel lock, and wakes a CPU that waits for it.
pub(crate) fn kernel_unlock() {
    KERNEL_LOCK.store(false, Ordering::SeqCst);
    let waiters = LOCK_WAITERS.load(Ordering::SeqCst);
    if waiters != 0 {
        // Each release wakes the next CPU after this one, so each CPU gets its turn. The timer
        // interrupt also wakes each CPU at each tick.
        let me = cpu::id() as u32;
        let next = waiters.rotate_right(me + 1).trailing_zeros();
        smp::reschedule(((me + 1 + next) % 64) as usize);
    }
}

/// The CPUs that wait for an interrupt in their idle task.
static IDLE_MASK: AtomicU64 = AtomicU64::new(0);

/// Wakes the CPU `id` if it waits in its idle task, so that it runs a task from its queue.
fn kick(id: usize) {
    if id != cpu::id() && id < 64 && IDLE_MASK.load(Ordering::Acquire) & 1 << id != 0 {
        smp::reschedule(id);
    }
}
/// An exited task that the next task drops after the switch, when its stack is not in use.
static EXITED_TASK: SpinLock<Option<Arc<Task>>> = SpinLock::new(None);

/// Makes a new task.
pub struct TaskOptions {
    entry: Entry,
    data: Box<dyn Any + Send + Sync>,
    nice: i32,
    idle: bool,
    affinity: u64,
    group: u32,
}

impl TaskOptions {
    /// Makes the options of a task that runs `entry`.
    pub fn new(entry: impl FnOnce() + Send + 'static) -> Self {
        Self {
            entry: Box::new(entry),
            data: Box::new(()),
            nice: 0,
            idle: false,
            affinity: u64::MAX,
            group: 0,
        }
    }

    /// Sets the nice value of the task, and if it has the smallest share of the CPU. See
    /// `Scheduler::set_nice`.
    pub fn nice(mut self, nice: i32, idle: bool) -> Self {
        self.nice = nice;
        self.idle = idle;
        self
    }

    /// Sets the CPUs that the task can use. See `Scheduler::set_affinity`.
    pub fn affinity(mut self, mask: u64) -> Self {
        self.affinity = mask;
        self
    }

    /// Sets the group of the task. See `Scheduler::set_group`.
    pub fn group(mut self, group: u32) -> Self {
        self.group = group;
        self
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
            run_start: AtomicU64::new(0),
            cpu_ns: AtomicU64::new(0),
            yield_tick: AtomicU64::new(u64::MAX),
            resched: AtomicBool::new(false),
            context: UnsafeCell::new(TaskContext::new(stack.top())),
            entry: SpinLock::new(Some(self.entry)),
            data: self.data,
            sched: Once::new(),
            _stack: Some(stack),
        });
        scheduler().set_group(&task, self.group);
        scheduler().set_nice(&task, self.nice, self.idle);
        scheduler().set_affinity(&task, self.affinity);
        kick(scheduler().enqueue(task.clone(), Enqueue::New));
        Some(task)
    }
}

impl Task {
    /// Gives the task on the CPU. The code that runs before the first task is the boot task.
    pub fn current() -> Arc<Task> {
        this_cpu().current.lock().get_or_insert_with(|| Task::on_boot_stack(0, RUNNING)).clone()
    }

    /// Makes the task of the code that runs on the boot stack of a CPU.
    fn on_boot_stack(id: u64, state: u8) -> Arc<Task> {
        Arc::new(Task {
            id,
            state: AtomicU8::new(state),
            start_tick: AtomicU64::new(crate::time::ticks()),
            run_start: AtomicU64::new(crate::time::nanos()),
            cpu_ns: AtomicU64::new(0),
            yield_tick: AtomicU64::new(u64::MAX),
            resched: AtomicBool::new(false),
            context: UnsafeCell::new(TaskContext::default()),
            entry: SpinLock::new(None),
            data: Box::new(()),
            sched: Once::new(),
            _stack: None,
        })
    }

    /// The number of the task. The boot task has the number 0.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// The data that `TaskOptions::data` gave.
    pub fn data(&self) -> &(dyn Any + Send + Sync) {
        &*self.data
    }

    /// The data of the scheduler for the task.
    pub fn sched_data(&self) -> &(dyn Any + Send + Sync) {
        &**self.sched.call_once(|| scheduler().new_data())
    }

    /// The nanoseconds that the task ran on a CPU, in user mode and in the kernel. The run of a
    /// task on the CPU now counts up to now.
    pub fn cpu_ns(&self) -> u64 {
        let done = self.cpu_ns.load(Ordering::Relaxed);
        if self.state.load(Ordering::Acquire) != RUNNING {
            return done;
        }
        let start = self.run_start.load(Ordering::Relaxed);
        done + crate::time::nanos().saturating_sub(start)
    }

    /// Tells if the task returned from its start function.
    pub fn is_exited(&self) -> bool {
        self.state.load(Ordering::Acquire) == EXITED
    }

    /// Tells if the task is the idle task of a CPU.
    pub fn is_idle(&self) -> bool {
        self.state.load(Ordering::Acquire) == IDLE
    }

    /// Tells if the task waits in a wait queue.
    pub fn is_blocked(&self) -> bool {
        self.state.load(Ordering::Acquire) == BLOCKED
    }

    /// Makes a blocked task runnable. Gives `false` if the task was not blocked.
    pub fn wake(self: &Arc<Self>) -> bool {
        let woken = self
            .state
            .compare_exchange(BLOCKED, RUNNABLE, Ordering::AcqRel, Ordering::Acquire)
            .is_ok();
        if woken {
            kick(scheduler().enqueue(self.clone(), Enqueue::Wake));
        }
        woken
    }
}

/// Tells if the current task ran for its time slice since it came on the CPU.
///
/// The scheduler looks at most one time in each timer tick, as the tick of Linux sets
/// `TIF_NEED_RESCHED`, so a task that makes many system calls does not pay for the check each
/// time. A change of the nice value, the CPUs or the group of the task makes it look again before
/// the next tick.
pub fn should_yield() -> bool {
    let now = crate::time::ticks();
    let this = this_cpu();
    // The first check does not copy the `Arc` of the task.
    let check = this.resched.swap(false, Ordering::Relaxed)
        || this.current.lock().as_ref().is_none_or(|current| {
            current.yield_tick.swap(now, Ordering::Relaxed) != now
                || current.resched.swap(false, Ordering::Relaxed)
        });
    if !check {
        return false;
    }
    let current = Task::current();
    let ran = now.wrapping_sub(current.start_tick.load(Ordering::Relaxed));
    scheduler().should_yield(&current, ran)
}

/// Asks the task on the CPU `id` to call `Scheduler::should_yield` before the next tick, as
/// `resched_curr` of Linux. The scheduler calls it when a task that wakes takes the CPU from the
/// task that runs. Another CPU gets an interrupt, so that a task in user mode comes back to the
/// kernel at once.
pub fn resched_cpu(id: usize) {
    let Some(target) = CPUS.get(id) else { return };
    target.resched.store(true, Ordering::Release);
    if id != cpu::id() {
        smp::reschedule(id);
    }
}

/// Sets the share of the CPU of `task`. See `Scheduler::set_nice`.
pub fn set_nice(task: &Task, nice: i32, idle: bool) {
    scheduler().set_nice(task, nice, idle);
    task.resched.store(true, Ordering::Relaxed);
}

/// Sets the CPUs that `task` can use. See `Scheduler::set_affinity`.
pub fn set_affinity(task: &Task, mask: u64) {
    if let Some(id) = scheduler().set_affinity(task, mask) {
        kick(id);
    }
    task.resched.store(true, Ordering::Relaxed);
}

/// Puts `task` in the group `group`. See `Scheduler::set_group`.
pub fn set_group(task: &Task, group: u32) {
    scheduler().set_group(task, group);
    task.resched.store(true, Ordering::Relaxed);
}

/// Lets the next task run. The current task stays runnable, so it runs again later.
pub fn yield_now() {
    let current = Task::current();
    if current.is_idle() || scheduler().runs_alone(&current) {
        return;
    }
    current.state.store(RUNNABLE, Ordering::Release);
    scheduler().put_prev(&current, false);
    kick(scheduler().enqueue(current, Enqueue::Yield));
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

/// Switches to the next task from the scheduler. If no task can run, the CPU switches to its idle
/// task. The current task is in the queue already if it can run.
fn schedule() {
    let _irq = IrqOff::new();
    let current = Task::current();
    let state = current.state.load(Ordering::Acquire);
    if state == BLOCKED || state == EXITED {
        scheduler().put_prev(&current, true);
    }
    let next = scheduler().dequeue().unwrap_or_else(idle_task);
    let now = crate::time::nanos();
    if state != IDLE {
        let ran = now.saturating_sub(current.run_start.load(Ordering::Relaxed));
        current.cpu_ns.fetch_add(ran, Ordering::Relaxed);
    }
    if !next.is_idle() {
        next.run_start.store(now, Ordering::Relaxed);
        next.state.store(RUNNING, Ordering::Release);
        next.start_tick.store(crate::time::ticks(), Ordering::Relaxed);
        scheduler().set_next(&next);
    }
    if Arc::ptr_eq(&current, &next) {
        return;
    }
    let from = current.context.get();
    let to = next.context.get().cast_const();
    *this_cpu().current.lock() = Some(next);
    if current.state.load(Ordering::Acquire) == EXITED {
        *EXITED_TASK.lock() = Some(current);
    } else {
        // The queue, a wait queue or a `wake` holds the current task, so its context lives.
        drop(current);
    }
    // SAFETY: interrupts are off, and the CPU holds the kernel lock, so no other CPU switches. `to`
    // is the context of `next`, which the current task of this CPU holds, and it is not on a CPU.
    // `from` is the context of the current task, which the CPU held until now and which a queue,
    // a wait queue, the idle task of the CPU or `EXITED_TASK` holds now.
    unsafe { switch(from, to) };
    finish_switch();
}

/// The idle task of this CPU. The idle task of the boot CPU is new at the first call. The idle task
/// of another CPU is the code on its boot stack, which `run_secondary` sets.
fn idle_task() -> Arc<Task> {
    this_cpu()
        .idle
        .call_once(|| {
            let stack = KernelStack::new().expect("no memory for the idle task");
            Arc::new(Task {
                id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
                state: AtomicU8::new(IDLE),
                start_tick: AtomicU64::new(0),
                run_start: AtomicU64::new(0),
                cpu_ns: AtomicU64::new(0),
                yield_tick: AtomicU64::new(u64::MAX),
                resched: AtomicBool::new(false),
                context: UnsafeCell::new(TaskContext::new(stack.top())),
                entry: SpinLock::new(Some(Box::new(|| idle_loop()))),
                data: Box::new(()),
                sched: Once::new(),
                _stack: Some(stack),
            })
        })
        .clone()
}

/// The loop of the idle task: it runs the other tasks, and waits for an interrupt when no task can
/// run. The bottom half of an interrupt can wake a task.
fn idle_loop() -> ! {
    let bit = 1 << cpu::id();
    loop {
        run_bottom_half();
        schedule();
        // The CPU holds the kernel lock, so a task that is made runnable after this point sees
        // the CPU in the mask and wakes it. An interrupt that comes before `wait` stays pending,
        // and `wait` takes it.
        IDLE_MASK.fetch_or(bit, Ordering::AcqRel);
        kernel_unlock();
        crate::irq::wait();
        crate::irq::disable();
        kernel_lock();
        IDLE_MASK.fetch_and(!bit, Ordering::AcqRel);
    }
}

/// The first code of a CPU that is not the boot CPU, after the CPU is set up. The code on the
/// boot stack of the CPU becomes its idle task.
pub(crate) fn run_secondary() -> ! {
    kernel_lock();
    let idle = Task::on_boot_stack(NEXT_ID.fetch_add(1, Ordering::Relaxed), IDLE);
    this_cpu().idle.call_once(|| idle.clone());
    *this_cpu().current.lock() = Some(idle);
    idle_loop()
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

/// Blocks the current task in each queue of `queues` until a wake of one of them or until the
/// tick count is at `deadline`. This is the wait of `poll` on the queues of more than one file, as
/// `poll_schedule_timeout` of Linux. The task tests `cond` after it is in the queues, so a wake
/// that comes after the last test of the caller is not lost. If `cond` gives a value, the task does
/// not block and the function gives the value. Else it gives `None` after the wake, and the caller
/// tests its condition again. A deadline of `u64::MAX` is no deadline.
pub fn wait_any<R>(
    queues: &[&WaitQueue],
    deadline: u64,
    cond: impl FnOnce() -> Option<R>,
) -> Option<R> {
    let current = Task::current();
    let key = (deadline, current.id);
    if deadline != u64::MAX {
        TIMERS.lock().insert(key, Arc::downgrade(&current));
    }
    current.state.store(BLOCKED, Ordering::Release);
    for queue in queues {
        queue.waiters.lock().push_back(current.clone());
    }
    let value = cond();
    if value.is_some() || crate::time::ticks() >= deadline {
        if current.state.swap(RUNNING, Ordering::AcqRel) == RUNNABLE {
            // A wake made the task runnable, as in `wait_until`.
            current.state.store(RUNNABLE, Ordering::Release);
            schedule();
        }
    } else {
        block();
    }
    // A wake takes the task from one queue only, so the task leaves the other queues here.
    for queue in queues {
        queue.waiters.lock().retain(|t| !Arc::ptr_eq(t, &current));
    }
    if deadline != u64::MAX {
        TIMERS.lock().remove(&key);
    }
    value
}

impl Default for WaitQueue {
    fn default() -> Self {
        Self::new()
    }
}
