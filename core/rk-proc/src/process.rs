//! Processes, threads and process IDs.
//!
//! A `Process` has an address space, a descriptor table, a file system context and one or more
//! threads. A `Thread` runs in one kernel task. The parent of a process waits for it with `wait4`,
//! and a process that ends stays as a zombie until its parent reaps it, as in Linux.

use crate::wait::{WaitStatus, WaitTarget};
use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use rk_abi::Errno;
use rk_frame::sync::SpinLock;
use rk_frame::task::{Task, WaitQueue};
use rk_frame::vm::VmSpace;
use rk_mm::AddressSpace;
use rk_vfs::{FdTable, FsContext};

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
    comm: Vec<u8>,
}

/// A process: a thread group in the words of Linux.
pub struct Process {
    pid: Pid,
    state: SpinLock<State>,
    /// The process waits here in `wait4` for a change of its children.
    child_wait: WaitQueue,
    vm: SpinLock<Option<Arc<AddressSpace>>>,
    files: SpinLock<Option<SharedFiles>>,
    fs: SpinLock<Option<SharedFs>>,
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
    /// The thread must stop at its next return to the kernel, because its group exits.
    killed: AtomicBool,
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

    fn new(
        pid: Pid,
        parent: Weak<Process>,
        pgid: Pid,
        sid: Pid,
        comm: Vec<u8>,
        vm: Arc<AddressSpace>,
        files: SharedFiles,
        fs: SharedFs,
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
                comm,
            }),
            child_wait: WaitQueue::new(),
            vm: SpinLock::new(Some(vm)),
            files: SpinLock::new(Some(files)),
            fs: SpinLock::new(Some(fs)),
        })
    }
}

impl Thread {
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

    fn new(tid: Pid, process: Arc<Process>) -> Arc<Self> {
        Arc::new(Self {
            tid,
            process,
            task: SpinLock::new(Weak::new()),
            clear_child_tid: AtomicUsize::new(0),
            killed: AtomicBool::new(false),
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
    );
    let thread = Thread::new(pid, process.clone());
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
    let mut table = TABLE.lock();
    let pid = alloc_pid(&mut table)?;
    let child = Process::new(pid, Arc::downgrade(pp), pgid, sid, comm, vm, files, fs);
    let thread = Thread::new(pid, child.clone());
    child.state.lock().threads.push(thread.clone());
    table.processes.insert(pid, Arc::downgrade(&child));
    table.threads.insert(pid, Arc::downgrade(&thread));
    drop(table);
    pp.state.lock().children.push(child);
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
    let new = Thread::new(tid, process.clone());
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

/// Ends `thread`. The caller then ends the task. If this is the last thread of its process, the
/// process ends: it closes its files, drops its address space, gives its children to init and
/// becomes a zombie for its parent. `status` is the status of the thread, and the status of the
/// group goes first.
pub fn exit_thread(thread: &Arc<Thread>, status: WaitStatus) {
    let process = thread.process.clone();
    TABLE.lock().threads.remove(&thread.tid);
    let last = {
        let mut s = process.state.lock();
        s.threads.retain(|t| t.tid != thread.tid);
        s.threads.is_empty()
    };
    if !last {
        return;
    }
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

/// Waits for a child of `process` that matches `target` to end, for `wait4` and `waitid`.
/// Gives the ID and the status of the child, or `None` with `WNOHANG` if no child ended yet.
/// `interrupted` tells if a signal must stop the wait.
///
/// # Errors
///
/// Gives `ECHILD` if no child matches, and `ERESTARTSYS` if `interrupted` gives `true`.
pub fn wait_child(
    process: &Process,
    target: WaitTarget,
    nohang: bool,
    reap: bool,
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
            if let Some(status) = c.state.lock().zombie {
                zombie = Some((i, c.pid, status));
                break;
            }
        }
        if let Some((i, pid, status)) = zombie {
            if reap {
                s.children.remove(i);
                drop(s);
                TABLE.lock().processes.remove(&pid);
            }
            return Some(Ok(Some((pid, status))));
        }
        if !found {
            return Some(Err(Errno::ECHILD));
        }
        if nohang {
            return Some(Ok(None));
        }
        if interrupted() {
            return Some(Err(Errno::ERESTARTSYS));
        }
        None
    })
}
