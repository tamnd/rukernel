//! Processes, threads and process IDs.
//!
//! A `Process` has an address space, a descriptor table, a file system context and one or more
//! threads. A `Thread` runs in one kernel task. The parent of a process waits for it with `wait4`,
//! and a process that ends stays as a zombie until its parent reaps it, as in Linux.

use crate::limits::{Limit, RLIM_NLIMITS, RLIMIT_CORE};
use crate::signal::{
    AltStack, NSIG, Pending, SI_TIMER, SIG_DFL, SIG_IGN, SigAction, SigInfo, SigSet,
};
use crate::timer::Timers;
use crate::wait::{WaitOptions, WaitStatus, WaitTarget};
use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};
use rk_abi::Errno;
use rk_abi::native::signal::{SA_NOCLDSTOP, SA_NOCLDWAIT, SIGCHLD, SIGCONT, SIGKILL};
use rk_frame::sync::{SpinLock, SpinLockGuard};
use rk_frame::task::{Task, WaitQueue};
use rk_frame::vm::VmSpace;
use rk_mm::AddressSpace;
use rk_vfs::{FdTable, FsContext, Location};

/// A process ID or a thread ID.
pub type Pid = u32;

/// The highest process ID plus one. Linux has the same default limit on 64 bit machines.
pub const PID_MAX: Pid = 4_194_304;

/// The process ID of init.
pub const INIT_PID: Pid = 1;

/// The longest name of a process, without the zero byte. Linux names it `TASK_COMM_LEN - 1`.
pub const COMM_LEN: usize = 15;

/// The descriptor table that threads share. `clone` with `CLONE_FILES` shares it.
pub type SharedFiles = Arc<SpinLock<FdTable>>;
/// The file system context that threads share. `clone` with `CLONE_FS` shares it.
pub type SharedFs = Arc<SpinLock<FsContext>>;

struct State {
    parent: Weak<Process>,
    children: Vec<Arc<Process>>,
    threads: Vec<Arc<Thread>>,
    pgid: Pid,
    sid: Pid,
    /// The status of the exit of the thread group, after `exit_group` or a fatal signal.
    group_exit: Option<WaitStatus>,
    /// The status that the parent gets. The process is a zombie when this is set.
    zombie: Option<WaitStatus>,
    /// The last stop or continue of the process that the parent did not take with a wait yet.
    report: Option<WaitStatus>,
    comm: Vec<u8>,
}

/// What `execve` gave the process: the arguments and the file of the program.
#[derive(Clone, Default)]
struct Image {
    /// The arguments, each one with a zero byte at its end, as `/proc/PID/cmdline` gives them.
    cmdline: Vec<u8>,
    /// The file of the program, for `/proc/PID/exe`.
    exe: Option<Location>,
}

/// The signal state that the threads of a process share: the actions and the queue of the
/// signals that any thread can take.
struct SharedSignals {
    actions: [SigAction; NSIG as usize],
    pending: Pending,
}

/// The signal state of one thread.
#[derive(Default)]
struct ThreadSignals {
    blocked: SigSet,
    pending: Pending,
    /// The mask that `rt_sigsuspend` replaced. The kernel puts it back after the delivery.
    saved_mask: Option<SigSet>,
    altstack: AltStack,
    /// The blocked signals that the thread waits for in `rt_sigtimedwait`. A signal in this set
    /// wakes the thread, and its action does not apply. Linux keeps the opposite set in
    /// `real_blocked`.
    waiting: SigSet,
}

/// What the thread must do with the next signal that it takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Delivery {
    /// Run the handler of the action.
    Handler(SigInfo, SigAction),
    /// End the process with this status.
    Fatal(WaitStatus),
    /// Stop the process with this signal.
    Stop(u32),
}

/// What `restart_syscall` continues: a system call that a signal without a handler or a stop
/// interrupted, as `struct restart_block` of Linux. `call` is the number of the system call, and
/// `args` hold its state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Restart {
    /// The number of the system call.
    pub call: u32,
    /// The state of the call, such as the end of a sleep.
    pub args: [u64; 3],
}

/// A process: a thread group in the words of Linux.
pub struct Process {
    pid: Pid,
    state: SpinLock<State>,
    /// The process waits here in `wait4` for a change of its children.
    child_wait: WaitQueue,
    /// `execve` waits here until the other threads of the process are gone.
    thread_exit: WaitQueue,
    /// A stop signal stopped the process, and `SIGCONT` did not continue it yet. It changes
    /// with the lock of `state`, but it is not in `state`, because a wait for a child checks it
    /// with that lock held.
    stopped: AtomicBool,
    /// The threads of a stopped process wait here until `SIGCONT` or `SIGKILL` comes.
    stop_wait: WaitQueue,
    vm: SpinLock<Option<Arc<AddressSpace>>>,
    files: SpinLock<Option<SharedFiles>>,
    fs: SpinLock<Option<SharedFs>>,
    signals: SpinLock<SharedSignals>,
    /// The signal that the parent gets when the process ends, or 0.
    exit_signal: u32,
    image: SpinLock<Image>,
    /// The tick of the timer when the process was made.
    start_tick: u64,
    /// The value of `/proc/PID/oom_score_adj`. rukernel has no OOM killer yet.
    oom_score_adj: AtomicI32,
    limits: SpinLock<[Limit; RLIM_NLIMITS]>,
    timers: SpinLock<Timers>,
}

impl core::fmt::Debug for Process {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Process").field("pid", &self.pid).finish_non_exhaustive()
    }
}

/// A thread of a process.
pub struct Thread {
    tid: Pid,
    process: Arc<Process>,
    task: SpinLock<Weak<Task>>,
    /// The address that `set_tid_address` or `CLONE_CHILD_CLEARTID` gave. At the exit, the kernel
    /// writes 0 there.
    clear_child_tid: AtomicUsize,
    /// The head of the robust futex list that `set_robust_list` gave, or 0.
    robust_list: AtomicUsize,
    /// The thread must stop at its next return to the kernel, because its group exits.
    killed: AtomicBool,
    signals: SpinLock<ThreadSignals>,
    /// The parent of a `vfork` child waits on this.
    vfork_done: SpinLock<Option<Arc<VforkDone>>>,
    /// The call that `restart_syscall` continues.
    restart: SpinLock<Option<Restart>>,
}

/// The wait of the parent of a `vfork` child. The parent waits until the child calls `execve` or
/// ends, as `CLONE_VFORK` tells, because the child uses the memory of the parent until then.
pub struct VforkDone {
    done: AtomicBool,
    wait: WaitQueue,
}

impl VforkDone {
    /// Makes a wait that is not done.
    pub fn new() -> Arc<Self> {
        Arc::new(Self { done: AtomicBool::new(false), wait: WaitQueue::new() })
    }

    /// Waits until the child calls `execve` or ends.
    pub fn wait(&self) {
        self.wait.wait_until(|| self.done.load(Ordering::Acquire).then_some(()));
    }

    fn complete(&self) {
        self.done.store(true, Ordering::Release);
        self.wait.wake_all();
    }
}

impl core::fmt::Debug for Thread {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Thread").field("tid", &self.tid).finish_non_exhaustive()
    }
}

struct Table {
    processes: BTreeMap<Pid, Weak<Process>>,
    threads: BTreeMap<Pid, Weak<Thread>>,
    next: Pid,
}

static TABLE: SpinLock<Table> =
    SpinLock::new(Table { processes: BTreeMap::new(), threads: BTreeMap::new(), next: INIT_PID });

/// Gives a free ID. An ID is in use while a thread, a process, a process group or a session has
/// it. Linux also starts again at 300 after a wrap, so that the low IDs stay for the system.
fn alloc_pid(table: &mut Table) -> Result<Pid, Errno> {
    let used = |t: &Table, pid: Pid| {
        t.threads.contains_key(&pid)
            || t.processes.contains_key(&pid)
            || t.processes.values().filter_map(Weak::upgrade).any(|p| {
                let s = p.state.lock();
                s.pgid == pid || s.sid == pid
            })
    };
    for _ in 0..PID_MAX {
        let pid = table.next;
        table.next = if pid + 1 >= PID_MAX { 300 } else { pid + 1 };
        if !used(table, pid) {
            return Ok(pid);
        }
    }
    Err(Errno::EAGAIN)
}

/// Gives the process with the ID `pid`.
pub fn find_process(pid: Pid) -> Option<Arc<Process>> {
    TABLE.lock().processes.get(&pid).and_then(Weak::upgrade)
}

/// Gives the thread with the ID `tid`.
pub fn find_thread(tid: Pid) -> Option<Arc<Thread>> {
    TABLE.lock().threads.get(&tid).and_then(Weak::upgrade)
}

/// Gives each process that is in the table.
pub fn processes() -> Vec<Arc<Process>> {
    TABLE.lock().processes.values().filter_map(Weak::upgrade).collect()
}

/// Gives the thread of the current task, or `None` for a kernel task.
pub fn current_thread() -> Option<Arc<Thread>> {
    Task::current().data().downcast_ref::<Arc<Thread>>().cloned()
}

impl Process {
    /// The process ID.
    pub fn pid(&self) -> Pid {
        self.pid
    }

    /// The ID of the parent, or 0 for init.
    pub fn ppid(&self) -> Pid {
        self.parent().map_or(0, |p| p.pid)
    }

    /// The parent, or `None` for init.
    pub fn parent(&self) -> Option<Arc<Process>> {
        self.state.lock().parent.upgrade()
    }

    /// The process group ID.
    pub fn pgid(&self) -> Pid {
        self.state.lock().pgid
    }

    /// The session ID.
    pub fn sid(&self) -> Pid {
        self.state.lock().sid
    }

    /// Moves the process to the process group `pgid`.
    pub fn set_pgid(&self, pgid: Pid) {
        self.state.lock().pgid = pgid;
    }

    /// Makes the process the leader of a new session and a new process group, for `setsid`.
    ///
    /// # Errors
    ///
    /// Gives `EPERM` if the process leads a process group already.
    pub fn set_sid(&self) -> Result<Pid, Errno> {
        let in_use = processes().iter().any(|p| p.pid != self.pid && p.pgid() == self.pid);
        let mut s = self.state.lock();
        if s.pgid == self.pid || in_use {
            return Err(Errno::EPERM);
        }
        s.pgid = self.pid;
        s.sid = self.pid;
        Ok(self.pid)
    }

    /// The children that the parent did not reap.
    pub fn children(&self) -> Vec<Arc<Process>> {
        self.state.lock().children.clone()
    }

    /// The threads.
    pub fn threads(&self) -> Vec<Arc<Thread>> {
        self.state.lock().threads.clone()
    }

    /// The name of the process, as `/proc/PID/comm` gives it.
    pub fn comm(&self) -> Vec<u8> {
        self.state.lock().comm.clone()
    }

    /// Sets the name of the process. Only the first `COMM_LEN` bytes stay.
    pub fn set_comm(&self, name: &[u8]) {
        let len = name.iter().position(|&b| b == 0).unwrap_or(name.len()).min(COMM_LEN);
        self.state.lock().comm = name[..len].to_vec();
    }

    /// The address space. A zombie has none.
    pub fn vm(&self) -> Option<Arc<AddressSpace>> {
        self.vm.lock().clone()
    }

    /// Puts a new address space in the process, for `execve`, and gives the old one.
    pub fn replace_vm(&self, vm: Arc<AddressSpace>) -> Option<Arc<AddressSpace>> {
        self.vm.lock().replace(vm)
    }

    /// The descriptor table. A zombie has none.
    pub fn files(&self) -> Option<SharedFiles> {
        self.files.lock().clone()
    }

    /// Puts a new descriptor table in the process, for `unshare(CLONE_FILES)` and `execve`.
    pub fn set_files(&self, files: SharedFiles) {
        *self.files.lock() = Some(files);
    }

    /// The file system context. A zombie has none.
    pub fn fs(&self) -> Option<SharedFs> {
        self.fs.lock().clone()
    }

    /// Tells if the process ended and waits for its parent.
    pub fn is_zombie(&self) -> bool {
        self.state.lock().zombie.is_some()
    }

    /// The status of the exit of the group, if the group exits.
    pub fn group_exit(&self) -> Option<WaitStatus> {
        self.state.lock().group_exit
    }

    /// The queue where the process waits for its children.
    pub fn child_wait(&self) -> &WaitQueue {
        &self.child_wait
    }

    /// The action of `sig`.
    pub fn action(&self, sig: u32) -> SigAction {
        self.signals.lock().actions[sig as usize - 1]
    }

    /// Sets the action of `sig` and gives the old one, for `rt_sigaction`. If the new action
    /// discards the signal, the pending instances go too, as POSIX tells.
    pub fn set_action(&self, sig: u32, action: SigAction) -> SigAction {
        let mut sigs = self.signals.lock();
        let old = core::mem::replace(&mut sigs.actions[sig as usize - 1], action);
        if action.ignores(sig) {
            sigs.pending.discard(sig);
            for t in self.threads() {
                t.signals.lock().pending.discard(sig);
            }
        }
        old
    }

    /// Sets each action that has a handler back to `SIG_DFL`, for `execve`. An ignored signal
    /// stays ignored.
    pub fn reset_actions(&self) {
        for a in &mut self.signals.lock().actions {
            if a.handler != SIG_IGN {
                *a = SigAction::default();
            }
        }
    }

    /// The arguments of the program, each one with a zero byte at its end.
    pub fn cmdline(&self) -> Vec<u8> {
        self.image.lock().cmdline.clone()
    }

    /// The file of the program, or `None` before the first `execve`.
    pub fn exe(&self) -> Option<Location> {
        self.image.lock().exe.clone()
    }

    /// Sets the arguments and the file of the program, after `execve`.
    pub fn set_image(&self, argv: &[Vec<u8>], exe: Location) {
        let mut cmdline = Vec::new();
        for arg in argv {
            cmdline.extend_from_slice(arg);
            cmdline.push(0);
        }
        *self.image.lock() = Image { cmdline, exe: Some(exe) };
    }

    /// The tick of the timer when the process was made.
    pub fn start_tick(&self) -> u64 {
        self.start_tick
    }

    /// The value of `/proc/PID/oom_score_adj`.
    pub fn oom_score_adj(&self) -> i32 {
        self.oom_score_adj.load(Ordering::Relaxed)
    }

    /// Sets the value of `/proc/PID/oom_score_adj`.
    pub fn set_oom_score_adj(&self, value: i32) {
        self.oom_score_adj.store(value, Ordering::Relaxed);
    }

    /// The soft and the hard limit of `resource`, which is less than `RLIM_NLIMITS`.
    pub fn limit(&self, resource: usize) -> Limit {
        self.limits.lock()[resource]
    }

    /// Sets the limit of `resource`. The caller checks the values.
    pub fn set_limit(&self, resource: usize, limit: Limit) {
        self.limits.lock()[resource] = limit;
    }

    /// The status of the process when `sig` ends it with the default action. The core dump bit
    /// is set for a signal that dumps core when `RLIMIT_CORE` is not 0. rukernel does not write
    /// the core file yet.
    pub fn fatal_status(&self, sig: u32) -> WaitStatus {
        let core = crate::signal::default_action(sig) == crate::signal::DefaultAction::CoreDump
            && self.limit(RLIMIT_CORE).cur != 0;
        WaitStatus::signaled(sig, core)
    }

    /// Tells if a stop signal stopped the process.
    pub fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::Acquire)
    }

    /// The state letter of `/proc/PID/stat`: `Z` for a zombie, `T` for a stopped process, `R` if
    /// a thread runs or can run, and `S` if each thread waits.
    pub fn state_letter(&self) -> u8 {
        let s = self.state.lock();
        if s.zombie.is_some() {
            return b'Z';
        }
        if self.is_stopped() {
            return b'T';
        }
        let running = s.threads.iter().any(|t| t.task().is_some_and(|task| !task.is_blocked()));
        if running { b'R' } else { b'S' }
    }

    /// The signals that any thread of the process can take.
    pub fn shared_pending(&self) -> SigSet {
        self.signals.lock().pending.set()
    }

    /// The interval timers and the POSIX timers of the process.
    pub fn timers(&self) -> SpinLockGuard<'_, Timers> {
        self.timers.lock()
    }

    /// The signal that the parent gets when the process ends, or 0.
    pub fn exit_signal(&self) -> u32 {
        self.exit_signal
    }

    #[allow(clippy::too_many_arguments)]
    fn new(
        pid: Pid,
        parent: Weak<Process>,
        pgid: Pid,
        sid: Pid,
        comm: Vec<u8>,
        vm: Arc<AddressSpace>,
        files: SharedFiles,
        fs: SharedFs,
        actions: [SigAction; NSIG as usize],
        exit_signal: u32,
    ) -> Arc<Self> {
        Arc::new(Self {
            pid,
            state: SpinLock::new(State {
                parent,
                children: Vec::new(),
                threads: Vec::new(),
                pgid,
                sid,
                group_exit: None,
                zombie: None,
                report: None,
                comm,
            }),
            child_wait: WaitQueue::new(),
            thread_exit: WaitQueue::new(),
            stopped: AtomicBool::new(false),
            stop_wait: WaitQueue::new(),
            vm: SpinLock::new(Some(vm)),
            files: SpinLock::new(Some(files)),
            fs: SpinLock::new(Some(fs)),
            signals: SpinLock::new(SharedSignals { actions, pending: Pending::new() }),
            exit_signal,
            image: SpinLock::new(Image::default()),
            start_tick: rk_frame::time::ticks(),
            oom_score_adj: AtomicI32::new(0),
            limits: SpinLock::new(crate::limits::defaults(
                rk_mm::STACK_SIZE as u64,
                u64::from(PID_MAX),
                rk_vfs::fdtable::NR_OPEN_DEFAULT as u64,
            )),
            timers: SpinLock::new(Timers::default()),
        })
    }
}

impl Thread {
    /// Sets the wait of the parent, for a child of `vfork`.
    pub fn set_vfork_done(&self, done: Arc<VforkDone>) {
        *self.vfork_done.lock() = Some(done);
    }

    /// Lets the parent of a `vfork` child continue. `execve` and the exit call it.
    pub(crate) fn release_vfork(&self) {
        if let Some(done) = self.vfork_done.lock().take() {
            done.complete();
        }
    }

    /// The thread ID.
    pub fn tid(&self) -> Pid {
        self.tid
    }

    /// The process.
    pub fn process(&self) -> &Arc<Process> {
        &self.process
    }

    /// Tells the thread which task runs it. The code that spawns the task calls this one time.
    pub fn set_task(&self, task: &Arc<Task>) {
        *self.task.lock() = Arc::downgrade(task);
    }

    /// The task that runs the thread.
    pub fn task(&self) -> Option<Arc<Task>> {
        self.task.lock().upgrade()
    }

    /// The address for `clear_child_tid`, or 0.
    pub fn clear_child_tid(&self) -> usize {
        self.clear_child_tid.load(Ordering::Relaxed)
    }

    /// Sets the address for `clear_child_tid`, for `set_tid_address`.
    pub fn set_clear_child_tid(&self, addr: usize) {
        self.clear_child_tid.store(addr, Ordering::Relaxed);
    }

    /// The address of the head of the robust futex list, or 0.
    pub fn robust_list(&self) -> usize {
        self.robust_list.load(Ordering::Relaxed)
    }

    /// Sets the address of the head of the robust futex list, for `set_robust_list`.
    pub fn set_robust_list(&self, addr: usize) {
        self.robust_list.store(addr, Ordering::Relaxed);
    }

    /// Keeps the call that `restart_syscall` continues, or removes it with `None`.
    pub fn set_restart(&self, restart: Option<Restart>) {
        *self.restart.lock() = restart;
    }

    /// Takes the call that `restart_syscall` continues.
    pub fn take_restart(&self) -> Option<Restart> {
        self.restart.lock().take()
    }

    /// Tells if the thread must stop, because its group exits.
    pub fn is_killed(&self) -> bool {
        self.killed.load(Ordering::Acquire)
    }

    fn kill(&self) {
        self.killed.store(true, Ordering::Release);
        if let Some(task) = self.task() {
            task.wake();
        }
    }

    /// Wakes the task of the thread, so that a wait sees a new signal.
    fn wake(&self) {
        if let Some(task) = self.task() {
            task.wake();
        }
    }

    /// The signals that the thread blocks.
    pub fn blocked(&self) -> SigSet {
        self.signals.lock().blocked
    }

    /// Sets the signals that the thread blocks. `SIGKILL` and `SIGSTOP` stay unblocked.
    pub fn set_blocked(&self, set: SigSet) {
        self.signals.lock().blocked = set.without(SigSet::UNBLOCKABLE);
    }

    /// Keeps `mask` to put back after the next delivery, for `rt_sigsuspend`.
    pub fn set_saved_mask(&self, mask: SigSet) {
        self.signals.lock().saved_mask = Some(mask);
    }

    /// Takes the mask that `rt_sigsuspend` replaced.
    pub fn take_saved_mask(&self) -> Option<SigSet> {
        self.signals.lock().saved_mask.take()
    }

    /// The pending signals of the thread and of its process.
    pub fn pending(&self) -> SigSet {
        let shared = self.process.signals.lock().pending.set();
        SigSet(shared.0 | self.signals.lock().pending.set().0)
    }

    /// Tells if a wait must stop: the group exits, the process stops, or a signal that is not
    /// blocked is pending.
    pub fn signal_pending(&self) -> bool {
        self.is_killed()
            || !self.pending().without(self.blocked()).is_empty()
            || self.process.is_stopped()
    }

    /// Waits while the process is stopped. The wait ends when `SIGCONT` continues the process or
    /// the group exits.
    pub fn wait_while_stopped(&self) {
        self.process
            .stop_wait
            .wait_until(|| (!self.process.is_stopped() || self.is_killed()).then_some(()));
    }

    /// The alternate signal stack.
    pub fn altstack(&self) -> AltStack {
        self.signals.lock().altstack
    }

    /// Sets the alternate signal stack.
    pub fn set_altstack(&self, stack: AltStack) {
        self.signals.lock().altstack = stack;
    }

    /// Takes the next signal that the thread does not block, first from its own queue and then
    /// from the queue of the process. A signal that its action discards goes away. Gives `None`
    /// if no signal is ready. For a handler with `SA_RESETHAND`, the handler goes back to
    /// `SIG_DFL`.
    pub fn dequeue_signal(&self) -> Option<Delivery> {
        loop {
            let mut shared = self.process.signals.lock();
            let mut own = self.signals.lock();
            let blocked = own.blocked;
            let info = own.pending.take(blocked).or_else(|| shared.pending.take(blocked))?;
            let sig = info.signo;
            let action = shared.actions[sig as usize - 1];
            if action.ignores(sig) {
                continue;
            }
            if action.is_fatal(sig) {
                return Some(Delivery::Fatal(self.process.fatal_status(sig)));
            }
            if action.is_stop(sig) {
                // init does not stop, as Linux does not stop a process with
                // `SIGNAL_UNKILLABLE`.
                if self.process.pid == INIT_PID {
                    continue;
                }
                return Some(Delivery::Stop(sig));
            }
            if action.flags & u64::from(rk_abi::native::signal::SA_RESETHAND) != 0 {
                // Linux keeps the flags, the mask and the restorer.
                shared.actions[sig as usize - 1].handler = SIG_DFL;
            }
            return Some(Delivery::Handler(info, action));
        }
    }

    /// Sets the blocked signals that the thread waits for, for `rt_sigtimedwait`. The empty set
    /// ends the wait.
    pub fn set_waiting(&self, set: SigSet) {
        self.signals.lock().waiting = set;
    }

    /// Takes the next pending signal that is in `set`, first from the queue of the thread and
    /// then from the queue of the process. The action of the signal does not apply. This is
    /// the dequeue of `rt_sigtimedwait` and `signalfd`.
    pub fn take_signal(&self, set: SigSet) -> Option<SigInfo> {
        let mut shared = self.process.signals.lock();
        let mut own = self.signals.lock();
        let others = SigSet(!set.0);
        own.pending.take(others).or_else(|| shared.pending.take(others))
    }

    /// Sends a signal to this thread, for `tkill`, `tgkill` and the exceptions. See
    /// `send_signal`.
    pub fn send_signal(self: &Arc<Self>, info: SigInfo) {
        deliver(&self.process, Some(self), info);
    }

    /// Sends a signal that an exception caused. The thread cannot block or ignore it: if it
    /// does, the action goes back to `SIG_DFL` and the signal ends the process, as
    /// `force_sig_info` of Linux does.
    pub fn force_signal(self: &Arc<Self>, info: SigInfo) {
        let sig = info.signo;
        {
            let mut shared = self.process.signals.lock();
            let mut own = self.signals.lock();
            let action = &mut shared.actions[sig as usize - 1];
            if action.handler == SIG_IGN || own.blocked.contains(sig) {
                *action = SigAction::default();
                own.blocked.remove(sig);
            }
        }
        self.send_signal(info);
    }

    fn new(tid: Pid, process: Arc<Process>, blocked: SigSet) -> Arc<Self> {
        Arc::new(Self {
            tid,
            process,
            task: SpinLock::new(Weak::new()),
            clear_child_tid: AtomicUsize::new(0),
            robust_list: AtomicUsize::new(0),
            killed: AtomicBool::new(false),
            signals: SpinLock::new(ThreadSignals { blocked, ..ThreadSignals::default() }),
            vfork_done: SpinLock::new(None),
            restart: SpinLock::new(None),
        })
    }
}

/// Makes init, the process with the ID 1. Its thread does not run yet: the caller spawns a task
/// for it after `exec`.
///
/// # Errors
///
/// Gives `ENOMEM` if no memory is free, or `EEXIST` if init is there already.
pub fn create_init(fs: FsContext) -> Result<Arc<Thread>, Errno> {
    let vm = Arc::new(AddressSpace::new()?);
    let mut table = TABLE.lock();
    if table.processes.contains_key(&INIT_PID) {
        return Err(Errno::EEXIST);
    }
    let pid = alloc_pid(&mut table)?;
    let files = Arc::new(SpinLock::new(FdTable::new()));
    let process = Process::new(
        pid,
        Weak::new(),
        pid,
        pid,
        b"init".to_vec(),
        vm,
        files,
        Arc::new(SpinLock::new(fs)),
        [SigAction::default(); NSIG as usize],
        0,
    );
    let thread = Thread::new(pid, process.clone(), SigSet::EMPTY);
    process.state.lock().threads.push(thread.clone());
    table.processes.insert(pid, Arc::downgrade(&process));
    table.threads.insert(pid, Arc::downgrade(&thread));
    Ok(thread)
}

/// What a new process shares with its parent. The other parts are copies.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ForkShare {
    /// `CLONE_VM`: the address space.
    pub vm: bool,
    /// `CLONE_FILES`: the descriptor table.
    pub files: bool,
    /// `CLONE_FS`: the root, the current directory and the umask.
    pub fs: bool,
    /// The signal that the parent gets when the child ends: the low byte of the `clone` flags.
    pub exit_signal: u32,
    /// `CLONE_PARENT`: the child gets the parent of the caller, and the exit signal of the
    /// caller.
    pub parent: bool,
}

/// Makes a child process of the process of `parent`, for `fork` and `clone` without
/// `CLONE_THREAD`. The thread of the child does not run yet: the caller spawns a task for it.
///
/// # Errors
///
/// Gives `ENOMEM` if no memory is free, or `EAGAIN` if no process ID is free.
pub fn fork(parent: &Thread, share: ForkShare) -> Result<Arc<Thread>, Errno> {
    let pp = &parent.process;
    let vm = pp.vm().ok_or(Errno::ESRCH)?;
    let vm = if share.vm { vm } else { Arc::new(vm.fork()?) };
    let files = pp.files().ok_or(Errno::ESRCH)?;
    let files = if share.files { files } else { Arc::new(SpinLock::new(files.lock().clone())) };
    let fs = pp.fs().ok_or(Errno::ESRCH)?;
    let fs = if share.fs { fs } else { Arc::new(SpinLock::new(fs.lock().clone())) };
    let (pgid, sid, comm) = {
        let s = pp.state.lock();
        (s.pgid, s.sid, s.comm.clone())
    };
    let actions = pp.signals.lock().actions;
    let (owner, exit_signal) = if share.parent {
        // Linux gives `EINVAL` for init, which has no parent.
        (pp.parent().ok_or(Errno::EINVAL)?, pp.exit_signal)
    } else {
        (pp.clone(), share.exit_signal)
    };
    let mut table = TABLE.lock();
    let pid = alloc_pid(&mut table)?;
    let child = Process::new(
        pid,
        Arc::downgrade(&owner),
        pgid,
        sid,
        comm,
        vm,
        files,
        fs,
        actions,
        exit_signal,
    );
    *child.image.lock() = pp.image.lock().clone();
    *child.limits.lock() = *pp.limits.lock();
    child.set_oom_score_adj(pp.oom_score_adj());
    let thread = Thread::new(pid, child.clone(), parent.blocked());
    child.state.lock().threads.push(thread.clone());
    table.processes.insert(pid, Arc::downgrade(&child));
    table.threads.insert(pid, Arc::downgrade(&thread));
    drop(table);
    owner.state.lock().children.push(child);
    Ok(thread)
}

/// Makes a new thread in the process of `thread`, for `clone` with `CLONE_THREAD`. The new thread
/// does not run yet: the caller spawns a task for it.
///
/// # Errors
///
/// Gives `EAGAIN` if no thread ID is free.
pub fn new_thread(thread: &Thread) -> Result<Arc<Thread>, Errno> {
    let process = thread.process.clone();
    let mut table = TABLE.lock();
    let tid = alloc_pid(&mut table)?;
    let new = Thread::new(tid, process.clone(), thread.blocked());
    table.threads.insert(tid, Arc::downgrade(&new));
    drop(table);
    process.state.lock().threads.push(new.clone());
    Ok(new)
}

/// The status and the waiters of the exit of init.
static INIT_EXIT: SpinLock<Option<WaitStatus>> = SpinLock::new(None);
static INIT_EXIT_WAIT: WaitQueue = WaitQueue::new();

/// Waits until init ends, and gives its status. Linux stops the kernel then. rukernel gives the
/// status to the boot code, so that the boot tests can examine it.
pub fn wait_for_init() -> WaitStatus {
    INIT_EXIT_WAIT.wait_until(|| *INIT_EXIT.lock())
}

/// Starts the exit of each thread of the group of `thread` with `status`, for `exit_group` and
/// a fatal signal. The other threads stop at their next return to the kernel. The first status
/// stays.
pub fn exit_group(thread: &Thread, status: WaitStatus) {
    let others: Vec<Arc<Thread>> = {
        let mut s = thread.process.state.lock();
        s.group_exit.get_or_insert(status);
        s.threads.iter().filter(|t| t.tid != thread.tid).cloned().collect()
    };
    for t in others {
        t.kill();
    }
}

/// Sends a signal to `process`, or to `thread` of that process if it is given.
///
/// An action that discards the signal discards it now. `SIGKILL`, and a signal that ends the
/// process with a thread that does not block it, start the exit of the group at once. Each other
/// signal goes in the queue, and a thread that does not block it wakes up.
fn deliver(process: &Process, thread: Option<&Arc<Thread>>, info: SigInfo) {
    let sig = info.signo;
    if sig == 0 || sig > NSIG || process.is_zombie() || process.group_exit().is_some() {
        return;
    }
    if sig == SIGKILL {
        kill_group(process, WaitStatus::signaled(sig, false));
        return;
    }
    let all = process.threads();
    // A stop signal discards each pending `SIGCONT`, and `SIGCONT` discards each pending stop
    // signal and continues the process, as `prepare_signal` of Linux does. This happens when the
    // signal is sent, so a handler or a blocked `SIGCONT` continues the process too.
    if SigSet::STOP.contains(sig) {
        discard_pending(process, &all, SigSet(SigSet::bit(SIGCONT)));
    } else if sig == SIGCONT {
        discard_pending(process, &all, SigSet::STOP);
        continue_group(process);
    }
    let threads = match thread {
        Some(t) => alloc::vec![t.clone()],
        None => all,
    };
    let mut shared = process.signals.lock();
    let action = shared.actions[sig as usize - 1];
    let target = threads
        .iter()
        .find(|t| {
            let s = t.signals.lock();
            !s.blocked.contains(sig) || s.waiting.contains(sig)
        })
        .cloned();
    // A thread that waits for the signal in `rt_sigtimedwait` takes it, so the action does not
    // apply.
    let handled = target.as_ref().is_some_and(|t| !t.signals.lock().waiting.contains(sig));
    if action.ignores(sig) && handled {
        return;
    }
    if action.is_fatal(sig) && handled {
        drop(shared);
        kill_group(process, process.fatal_status(sig));
        return;
    }
    match thread {
        Some(t) => {
            t.signals.lock().pending.push(info);
        }
        None => {
            shared.pending.push(info);
        }
    }
    drop(shared);
    if let Some(t) = target {
        t.wake();
    }
}

/// Discards each pending signal of `set` in the queue of `process` and of each of its `threads`.
fn discard_pending(process: &Process, threads: &[Arc<Thread>], set: SigSet) {
    let mut shared = process.signals.lock();
    for sig in 1..=NSIG {
        if set.contains(sig) {
            shared.pending.discard(sig);
            for t in threads {
                t.signals.lock().pending.discard(sig);
            }
        }
    }
}

/// Stops the process of `thread` with the stop signal `sig`, and tells the parent. The threads
/// stop at their next return to the kernel, and wait there until `SIGCONT` comes.
pub fn stop_group(thread: &Thread, sig: u32) {
    let process = &thread.process;
    let (others, parent) = {
        let mut s = process.state.lock();
        if s.group_exit.is_some() || process.is_stopped() {
            return;
        }
        process.stopped.store(true, Ordering::Release);
        s.report = Some(WaitStatus::stopped(sig));
        let others: Vec<Arc<Thread>> =
            s.threads.iter().filter(|t| t.tid != thread.tid).cloned().collect();
        (others, s.parent.upgrade())
    };
    for t in others {
        t.wake();
    }
    if let Some(parent) = parent {
        notify_stop(process, &parent, WaitStatus::stopped(sig));
    }
}

/// Continues `process` if it is stopped, and tells the parent.
fn continue_group(process: &Process) {
    let parent = {
        let mut s = process.state.lock();
        if !process.is_stopped() {
            return;
        }
        process.stopped.store(false, Ordering::Release);
        s.report = Some(WaitStatus::CONTINUED);
        s.parent.upgrade()
    };
    process.stop_wait.wake_all();
    if let Some(parent) = parent {
        notify_stop(process, &parent, WaitStatus::CONTINUED);
    }
}

/// Tells the parent that `process` stopped or continued: it sends `SIGCHLD` if the parent did not
/// set `SA_NOCLDSTOP`, and wakes the waits of the parent.
fn notify_stop(process: &Process, parent: &Process, status: WaitStatus) {
    if parent.action(SIGCHLD).flags & u64::from(SA_NOCLDSTOP) == 0 {
        let (code, value) = status.child_code();
        let mut info = SigInfo::new(SIGCHLD, code, process.pid);
        info.status = value;
        send_signal(parent, info);
    }
    parent.child_wait.wake_all();
}

/// Sends the signal of a timer to `process`, or to `thread` of that process if it is given. In
/// `info`, `uid` holds the overrun count. If the last signal of the same POSIX timer is still
/// pending, the signal only adds its overruns to it. Gives the overrun count of the signal in the
/// queue.
pub(crate) fn send_timer_signal(
    process: &Process,
    thread: Option<&Arc<Thread>>,
    info: SigInfo,
) -> Option<i32> {
    if info.code == SI_TIMER {
        let mut shared = process.signals.lock();
        let more = info.uid.saturating_add(1);
        let count = match thread {
            Some(t) => t.signals.lock().pending.add_overrun(info.pid, more),
            None => shared.pending.add_overrun(info.pid, more),
        };
        if count.is_some() {
            return count;
        }
    }
    deliver(process, thread, info);
    Some(info.uid as i32)
}

/// Sends a signal to each thread of `process`, for `kill` and the signals of the terminal.
pub fn send_signal(process: &Process, info: SigInfo) {
    deliver(process, None, info);
}

/// Tells the parent of `process` that the process ended with `status`: it sends the exit signal,
/// and gives `true` if the parent ignores `SIGCHLD` or has `SA_NOCLDWAIT`. The process is then
/// reaped at once, as in Linux.
fn notify_parent(process: &Process, parent: &Process, status: WaitStatus) -> bool {
    let action = parent.action(SIGCHLD);
    let mut sig = process.exit_signal;
    let mut autoreap = false;
    if sig == SIGCHLD {
        if action.handler == SIG_IGN {
            autoreap = true;
            sig = 0;
        } else if action.flags & u64::from(SA_NOCLDWAIT) != 0 {
            autoreap = true;
        }
    }
    if sig != 0 {
        let (code, value) = status.child_code();
        let mut info = SigInfo::new(sig, code, process.pid);
        info.status = value;
        send_signal(parent, info);
    }
    autoreap
}

/// Starts the exit of each thread of `process` with `status`, for a fatal signal from another
/// process. Each thread stops at its next return to the kernel. The first status stays.
pub fn kill_group(process: &Process, status: WaitStatus) {
    let threads: Vec<Arc<Thread>> = {
        let mut s = process.state.lock();
        s.group_exit.get_or_insert(status);
        s.threads.clone()
    };
    for t in threads {
        t.kill();
    }
}

/// Ends each other thread of the process of `thread`, and waits until they are gone, as
/// `de_thread` of Linux does. `execve` calls it before it replaces the program, because the other
/// threads cannot run in the new program.
pub(crate) fn kill_other_threads(thread: &Thread) {
    let process = &thread.process;
    let others: Vec<Arc<Thread>> =
        process.state.lock().threads.iter().filter(|t| t.tid != thread.tid).cloned().collect();
    if others.is_empty() {
        return;
    }
    for t in &others {
        t.kill();
    }
    drop(others);
    process.thread_exit.wait_until(|| (process.state.lock().threads.len() <= 1).then_some(()));
}

/// Ends `thread`. The caller then ends the task. If this is the last thread of its process, the
/// process ends: it closes its files, drops its address space, gives its children to init and
/// becomes a zombie for its parent. `status` is the status of the thread, and the status of the
/// group goes first.
pub fn exit_thread(thread: &Arc<Thread>, status: WaitStatus) {
    thread.release_vfork();
    let process = thread.process.clone();
    TABLE.lock().threads.remove(&thread.tid);
    let last = {
        let mut s = process.state.lock();
        s.threads.retain(|t| t.tid != thread.tid);
        s.threads.is_empty()
    };
    if !last {
        process.thread_exit.wake_all();
        return;
    }
    process.timers().clear(false);
    // The task runs on the page table of the address space, so the kernel table goes first.
    VmSpace::deactivate();
    let vm = process.vm.lock().take();
    let files = process.files.lock().take();
    let fs = process.fs.lock().take();
    drop((vm, files, fs));

    let (children, parent, status) = {
        let mut s = process.state.lock();
        let status = s.group_exit.unwrap_or(status);
        s.zombie = Some(status);
        (core::mem::take(&mut s.children), s.parent.upgrade(), status)
    };
    let init = find_process(INIT_PID).filter(|init| !Arc::ptr_eq(init, &process));
    if let Some(init) = &init {
        let zombies = children.iter().any(|c| c.is_zombie());
        for child in &children {
            child.state.lock().parent = Arc::downgrade(init);
        }
        init.state.lock().children.extend(children);
        if zombies {
            init.child_wait.wake_all();
        }
    }
    match parent {
        Some(parent) => {
            if notify_parent(&process, &parent, status) {
                parent.state.lock().children.retain(|c| !Arc::ptr_eq(c, &process));
                TABLE.lock().processes.remove(&process.pid);
            }
            parent.child_wait.wake_all();
        }
        None if process.pid == INIT_PID => {
            TABLE.lock().processes.remove(&INIT_PID);
            *INIT_EXIT.lock() = Some(status);
            INIT_EXIT_WAIT.wake_all();
        }
        None => {
            TABLE.lock().processes.remove(&process.pid);
        }
    }
}

/// Waits for a child of `process` that matches `target` to end, stop or continue, as `options`
/// tells, for `wait4` and `waitid`. Gives the ID and the status of the child, or `None` with
/// `WNOHANG` if no child changed yet. Without `WNOWAIT`, the wait reaps the child that ended, or
/// takes the report of the stop or the continue. `interrupted` tells if a signal must stop the
/// wait.
///
/// # Errors
///
/// Gives `ECHILD` if no child matches, and `ERESTARTSYS` if `interrupted` gives `true`.
pub fn wait_child(
    process: &Process,
    target: WaitTarget,
    options: WaitOptions,
    mut interrupted: impl FnMut() -> bool,
) -> Result<Option<(Pid, WaitStatus)>, Errno> {
    process.child_wait.wait_until(|| {
        let mut s = process.state.lock();
        let matches = |c: &Arc<Process>| match target {
            WaitTarget::Any => true,
            WaitTarget::Pid(pid) => c.pid == pid,
            WaitTarget::Pgid(pgid) => c.pgid() == pgid,
        };
        let mut found = false;
        let mut zombie = None;
        for (i, c) in s.children.iter().enumerate() {
            if !matches(c) {
                continue;
            }
            found = true;
            let mut cs = c.state.lock();
            if let Some(status) = cs.zombie {
                if options.exited {
                    zombie = Some((i, c.pid, status));
                    break;
                }
                continue;
            }
            let report = cs.report.filter(|r| {
                if r.stop_signal().is_some() { options.stopped } else { options.continued }
            });
            if let Some(status) = report {
                if !options.nowait {
                    cs.report = None;
                }
                return Some(Ok(Some((c.pid, status))));
            }
        }
        if let Some((i, pid, status)) = zombie {
            if !options.nowait {
                s.children.remove(i);
                drop(s);
                TABLE.lock().processes.remove(&pid);
            }
            return Some(Ok(Some((pid, status))));
        }
        if !found {
            return Some(Err(Errno::ECHILD));
        }
        if options.nohang {
            return Some(Ok(None));
        }
        if interrupted() {
            return Some(Err(Errno::ERESTARTSYS));
        }
        None
    })
}
