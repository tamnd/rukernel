//! The network namespaces, as net/core/net_namespace.c of Linux.
//!
//! A namespace has its own devices, addresses, routes, neighbours and sockets. Each table of a
//! protocol is a `PerNet`, which gives the value of the current namespace. The current namespace
//! is the namespace that `enter` set for the task, else the namespace of the process. A socket, a
//! device and the poll of the devices enter their namespace, so the stack uses the correct
//! tables. When only the first namespace exists, `PerNet` uses it without a search.
//!
//! Linux gives each `struct net` a pointer to each table. Here a namespace has an index, and a
//! `PerNet` keeps one value for each index. A new namespace that gets the index of a dead one
//! clears the old values.

use crate::{Message, PathOps, Received, Socket};
use alloc::boxed::Box;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::any::Any;
use core::ops::Deref;
use core::sync::atomic::{AtomicU16, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use rk_abi::Errno;
use rk_frame::sync::{Once, SpinLock};
use rk_vfs::UserMemory;
use rk_vfs::inode::Result;
use rk_vfs::wait::PollTable;

/// The most namespaces at one time.
const MAX_NS: usize = 4096;

/// A network namespace, as `struct net` of Linux. The namespace stops when the last reference
/// goes: its virtual devices go away, and its other devices go back to the first namespace.
pub struct NetNs {
    index: usize,
    generation: u64,
}

impl NetNs {
    /// The index of the namespace. The first namespace has the index 0.
    pub fn index(&self) -> usize {
        self.index
    }

    /// The ID of the namespace, for the file of the namespace in nsfs. The first namespace has
    /// the ID 0, and each other namespace has a different ID.
    pub fn id(&self) -> u32 {
        // A generation is not 0 for a namespace other than the first one.
        self.generation as u32
    }

    /// Tells if this is the first namespace, `init_net` of Linux.
    pub fn is_init(&self) -> bool {
        self.index == 0
    }
}

impl core::fmt::Debug for NetNs {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NetNs").field("index", &self.index).field("id", &self.id()).finish()
    }
}

impl Drop for NetNs {
    fn drop(&mut self) {
        if self.index == 0 {
            return;
        }
        {
            let _in = Guard::push(self.index, self.generation);
            let ops = OPS.lock().clone();
            for op in ops.iter().rev() {
                (op.exit)();
            }
        }
        if let Some(slot) = REGISTRY.lock().get_mut(self.index) {
            *slot = None;
        }
        LIVE.fetch_sub(1, Ordering::AcqRel);
    }
}

/// A namespace in the registry: its generation and a weak reference.
struct Entry {
    generation: u64,
    ns: Weak<NetNs>,
}

/// The namespaces by index. The index 0 is the first namespace, which `INIT` holds.
static REGISTRY: SpinLock<Vec<Option<Entry>>> = SpinLock::new(Vec::new());
/// The count of namespaces, with the first one.
static LIVE: AtomicUsize = AtomicUsize::new(1);
/// The generation of the next namespace. Two namespaces with the same index have different
/// generations.
static NEXT_GEN: AtomicU64 = AtomicU64::new(1);
static INIT: Once<Arc<NetNs>> = Once::new();

/// The first namespace, `init_net` of Linux.
pub fn init_ns() -> Arc<NetNs> {
    INIT.call_once(|| Arc::new(NetNs { index: 0, generation: 0 })).clone()
}

/// The count of namespaces that exist now, with the first one.
pub fn count() -> usize {
    LIVE.load(Ordering::Acquire)
}

/// The functions that make and stop the parts of a namespace, as `struct pernet_operations` of
/// Linux.
#[derive(Clone, Copy)]
struct Ops {
    init: fn(),
    exit: fn(),
    device: bool,
}

/// The functions of `add_ops` and then the functions of `add_device_ops`, as `pernet_list` of
/// Linux.
static OPS: SpinLock<Vec<Ops>> = SpinLock::new(Vec::new());

/// Adds the functions that make and stop the parts of each new namespace, as
/// `register_pernet_subsys` of Linux. `init` runs in a new namespace. `exit` runs in a namespace
/// that stops, in the reverse order of the calls, after the functions of the devices. The first
/// namespace does not run them.
pub fn add_ops(init: fn(), exit: fn()) {
    let mut ops = OPS.lock();
    let at = ops.iter().position(|o| o.device).unwrap_or(ops.len());
    ops.insert(at, Ops { init, exit, device: false });
}

/// Adds the functions of the devices of each new namespace, as `register_pernet_device` of
/// Linux. They run after the functions of `add_ops` in a new namespace, and before them in a
/// namespace that stops.
pub fn add_device_ops(init: fn(), exit: fn()) {
    OPS.lock().push(Ops { init, exit, device: true });
}

/// Makes a new namespace, as `copy_net_ns` of Linux. Gives `ENOSPC` if too many namespaces
/// exist.
pub fn new() -> Result<Arc<NetNs>> {
    let generation = NEXT_GEN.fetch_add(1, Ordering::Relaxed);
    let ns = {
        let mut reg = REGISTRY.lock();
        if reg.is_empty() {
            reg.push(None);
        }
        let index = match reg.iter().skip(1).position(Option::is_none) {
            Some(i) => i + 1,
            None if reg.len() < MAX_NS => {
                reg.push(None);
                reg.len() - 1
            }
            None => return Err(Errno::ENOSPC),
        };
        let ns = Arc::new(NetNs { index, generation });
        reg[index] = Some(Entry { generation, ns: Arc::downgrade(&ns) });
        ns
    };
    LIVE.fetch_add(1, Ordering::AcqRel);
    let _in = enter(&ns);
    let ops = OPS.lock().clone();
    for op in ops {
        (op.init)();
    }
    Ok(ns)
}

/// Gives the namespace with the index `index`, if it exists and does not stop.
pub fn by_index(index: usize) -> Option<Arc<NetNs>> {
    if index == 0 {
        return Some(init_ns());
    }
    REGISTRY.lock().get(index)?.as_ref()?.ns.upgrade()
}

/// Gives the namespace with the ID `id`, if it exists and does not stop. The ID 0 is the first
/// namespace.
pub fn by_id(id: u32) -> Option<Arc<NetNs>> {
    if id == 0 {
        return Some(init_ns());
    }
    let reg = REGISTRY.lock();
    reg.iter().flatten().filter(|e| e.generation as u32 == id).find_map(|e| e.ns.upgrade())
}

/// The indexes of the namespaces that exist now, with the namespaces that stop.
pub fn indices() -> Vec<usize> {
    let reg = REGISTRY.lock();
    let others = reg.iter().enumerate().skip(1).filter(|(_, e)| e.is_some()).map(|(i, _)| i);
    core::iter::once(0).chain(others).collect()
}

/// A function that gives the namespace of the current process.
pub type Source = fn() -> Option<Arc<NetNs>>;

/// The function that gives the namespace of the current process.
static SOURCE: SpinLock<Option<Source>> = SpinLock::new(None);

/// Sets the function that gives the namespace of the current process. The process layer calls
/// this one time at boot. A task without a process uses the first namespace.
pub fn set_source(f: Source) {
    *SOURCE.lock() = Some(f);
}

/// The functions that find the namespace of a process and of a file, for `IFLA_NET_NS_PID` and
/// `IFLA_NET_NS_FD`.
#[derive(Clone, Copy)]
pub struct Resolver {
    /// Gives the namespace of the process `pid`. Gives `ESRCH` if there is no such process.
    pub by_pid: fn(i32) -> Result<Arc<NetNs>>,
    /// Gives the namespace of the file `fd` of the current process, which must be a file of
    /// `/proc/PID/ns/net`. Gives `EBADF` or `EINVAL` for another file.
    pub by_fd: fn(i32) -> Result<Arc<NetNs>>,
}

static RESOLVER: SpinLock<Option<Resolver>> = SpinLock::new(None);

/// Sets the functions that find a namespace. The process layer calls this one time at boot.
pub fn set_resolver(r: Resolver) {
    *RESOLVER.lock() = Some(r);
}

/// Gives the namespace of the process `pid`, as `get_net_ns_by_pid` of Linux.
pub fn by_pid(pid: i32) -> Result<Arc<NetNs>> {
    let r = *RESOLVER.lock();
    r.map_or(Err(Errno::ESRCH), |r| (r.by_pid)(pid))
}

/// Gives the namespace of the file `fd`, as `get_net_ns_by_fd` of Linux.
pub fn by_fd(fd: i32) -> Result<Arc<NetNs>> {
    let r = *RESOLVER.lock();
    r.map_or(Err(Errno::EINVAL), |r| (r.by_fd)(fd))
}

/// The namespaces that `enter` set: the task, the index and the generation, in the order of the
/// calls.
static ENTERED: SpinLock<Vec<(u64, usize, u64)>> = SpinLock::new(Vec::new());

/// The key of the current task. On the host each thread of the tests has its own key.
#[cfg(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64")))]
fn task_key() -> u64 {
    rk_frame::task::Task::current().id()
}

/// The key of the current task. A target without tasks has one key.
#[cfg(all(target_os = "none", not(any(target_arch = "x86_64", target_arch = "aarch64"))))]
fn task_key() -> u64 {
    0
}

/// The key of the current task. On the host each thread of the tests has its own key.
#[cfg(not(target_os = "none"))]
fn task_key() -> u64 {
    extern crate std;
    static NEXT: AtomicU64 = AtomicU64::new(1);
    std::thread_local! {
        static KEY: u64 = NEXT.fetch_add(1, Ordering::Relaxed);
    }
    KEY.with(|k| *k)
}

/// The index and the generation of the current namespace.
fn current_id() -> (usize, u64) {
    if LIVE.load(Ordering::Acquire) == 1 {
        return (0, 0);
    }
    let task = task_key();
    if let Some(&(_, index, generation)) = ENTERED.lock().iter().rev().find(|e| e.0 == task) {
        return (index, generation);
    }
    let source = *SOURCE.lock();
    source.and_then(|f| f()).map_or((0, 0), |ns| (ns.index, ns.generation))
}

/// The index of the current namespace.
pub fn current_index() -> usize {
    current_id().0
}

/// The current namespace, as `current->nsproxy->net_ns` of Linux, or the namespace that
/// `enter` set.
pub fn current() -> Arc<NetNs> {
    by_index(current_index()).unwrap_or_else(init_ns)
}

/// The guard of `enter`. The task leaves the namespace when the guard goes.
#[must_use]
pub struct Guard {
    task: u64,
    active: bool,
}

impl Guard {
    fn push(index: usize, generation: u64) -> Self {
        if LIVE.load(Ordering::Acquire) == 1 && index == 0 {
            return Self { task: 0, active: false };
        }
        let task = task_key();
        ENTERED.lock().push((task, index, generation));
        Self { task, active: true }
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let mut entered = ENTERED.lock();
        if let Some(at) = entered.iter().rposition(|e| e.0 == self.task) {
            entered.remove(at);
        }
    }
}

/// Makes `ns` the current namespace of the task until the guard goes.
pub fn enter(ns: &NetNs) -> Guard {
    Guard::push(ns.index, ns.generation)
}

/// Makes the namespace with the index `index` the current namespace of the task until the guard
/// goes. This works for a namespace that stops too. An index without a namespace gives the
/// first namespace.
pub fn enter_index(index: usize) -> Guard {
    if index == 0 {
        return Guard::push(0, 0);
    }
    let generation = REGISTRY.lock().get(index).and_then(|e| e.as_ref().map(|e| e.generation));
    match generation {
        Some(g) => Guard::push(index, g),
        None => Guard::push(0, 0),
    }
}

/// A value that a new namespace can clear. `PerNet` clears the value of a dead namespace when a
/// new namespace gets its index.
pub trait Clear {
    /// Changes the value to `fresh`.
    fn clear(&self, fresh: Self);
}

impl<T> Clear for SpinLock<T> {
    fn clear(&self, fresh: Self) {
        let old = core::mem::replace(&mut *self.lock(), fresh.into_inner());
        // The old value goes after the lock, because its drop can use the table again.
        drop(old);
    }
}

impl Clear for AtomicU64 {
    fn clear(&self, fresh: Self) {
        self.store(fresh.into_inner(), Ordering::Relaxed);
    }
}

impl Clear for AtomicU32 {
    fn clear(&self, fresh: Self) {
        self.store(fresh.into_inner(), Ordering::Relaxed);
    }
}

impl Clear for AtomicU16 {
    fn clear(&self, fresh: Self) {
        self.store(fresh.into_inner(), Ordering::Relaxed);
    }
}

/// A value for each namespace, as the fields of `struct net` and `net_generic` of Linux. It
/// dereferences to the value of the current namespace. The value of a namespace is made at the
/// first use, and it stays for the next namespace with the same index.
pub struct PerNet<T: 'static> {
    make: fn() -> T,
    first: Once<T>,
    others: SpinLock<Vec<Option<(u64, &'static T)>>>,
}

impl<T: Clear + Send + Sync + 'static> PerNet<T> {
    /// Makes the container. `make` gives the value for a new namespace.
    pub const fn new(make: fn() -> T) -> Self {
        Self { make, first: Once::new(), others: SpinLock::new(Vec::new()) }
    }

    /// The value of the current namespace.
    pub fn get(&self) -> &T {
        let (index, generation) = current_id();
        self.at(index, generation)
    }

    /// The value of the first namespace.
    pub fn first(&self) -> &T {
        self.first.call_once(self.make)
    }

    fn at(&self, index: usize, generation: u64) -> &T {
        if index == 0 {
            return self.first();
        }
        let (value, stale) = {
            let mut others = self.others.lock();
            if others.len() < index {
                others.resize(index, None);
            }
            match others[index - 1] {
                Some((g, v)) if g == generation => (v, false),
                Some((_, v)) => {
                    others[index - 1] = Some((generation, v));
                    (v, true)
                }
                None => {
                    let v: &'static T = Box::leak(Box::new((self.make)()));
                    others[index - 1] = Some((generation, v));
                    (v, false)
                }
            }
        };
        if stale {
            value.clear((self.make)());
        }
        value
    }

    /// Clears the value of the current namespace, for the `exit` function of `add_ops`. The
    /// first namespace keeps its value.
    pub fn reset(&self) {
        let (index, _) = current_id();
        if index == 0 {
            return;
        }
        let value = self.others.lock().get(index - 1).copied().flatten();
        if let Some((_, v)) = value {
            v.clear((self.make)());
        }
    }
}

impl<T: Clear + Send + Sync + 'static> Deref for PerNet<T> {
    type Target = T;

    fn deref(&self) -> &T {
        self.get()
    }
}

/// A socket that runs each operation in its namespace, as `sock_net` of Linux. The system call
/// layer puts each new socket of a family with namespaces in one.
pub struct NsSocket {
    net: Arc<NetNs>,
    inner: Arc<dyn Socket>,
}

impl NsSocket {
    /// Puts `inner` in the namespace `net`. The `as_any` of the wrapper gives the socket in it,
    /// so the operations of one family still find their type.
    pub fn wrap(net: Arc<NetNs>, inner: Arc<dyn Socket>) -> Arc<dyn Socket> {
        Arc::new(Self { net, inner })
    }

    /// The namespace of the socket.
    pub fn net(&self) -> &Arc<NetNs> {
        &self.net
    }
}

/// The namespace of `sock`: the namespace of an `NsSocket`, else the first namespace.
pub fn of_socket(sock: &dyn Socket) -> Arc<NetNs> {
    sock.netns().cloned().unwrap_or_else(init_ns)
}

impl Socket for NsSocket {
    fn family(&self) -> u32 {
        self.inner.family()
    }

    fn kind(&self) -> u32 {
        self.inner.kind()
    }

    fn protocol(&self) -> u32 {
        self.inner.protocol()
    }

    fn ino(&self) -> u64 {
        self.inner.ino()
    }

    fn bind(&self, paths: &dyn PathOps, addr: &[u8]) -> Result<()> {
        let _in = enter(&self.net);
        self.inner.bind(paths, addr)
    }

    fn connect(&self, paths: &dyn PathOps, addr: &[u8], nonblock: bool) -> Result<()> {
        let _in = enter(&self.net);
        self.inner.connect(paths, addr, nonblock)
    }

    fn listen(&self, backlog: u32) -> Result<()> {
        let _in = enter(&self.net);
        self.inner.listen(backlog)
    }

    fn accept(&self, nonblock: bool) -> Result<Arc<dyn Socket>> {
        let _in = enter(&self.net);
        let s = self.inner.accept(nonblock)?;
        Ok(Self::wrap(self.net.clone(), s))
    }

    fn send(&self, paths: &dyn PathOps, msg: Message, flags: u32, nonblock: bool) -> Result<usize> {
        let _in = enter(&self.net);
        self.inner.send(paths, msg, flags, nonblock)
    }

    fn recv(&self, len: usize, flags: u32, nonblock: bool) -> Result<Received> {
        let _in = enter(&self.net);
        self.inner.recv(len, flags, nonblock)
    }

    fn shutdown(&self, how: u32) -> Result<()> {
        let _in = enter(&self.net);
        self.inner.shutdown(how)
    }

    fn name(&self) -> Vec<u8> {
        let _in = enter(&self.net);
        self.inner.name()
    }

    fn peer_name(&self) -> Result<Vec<u8>> {
        let _in = enter(&self.net);
        self.inner.peer_name()
    }

    fn get_option(&self, level: u32, name: u32) -> Result<Vec<u8>> {
        let _in = enter(&self.net);
        self.inner.get_option(level, name)
    }

    fn set_option(&self, level: u32, name: u32, value: &[u8]) -> Result<()> {
        let _in = enter(&self.net);
        self.inner.set_option(level, name, value)
    }

    fn option_input(&self, level: u32, name: u32) -> usize {
        self.inner.option_input(level, name)
    }

    fn get_option_in(&self, level: u32, name: u32, input: &[u8]) -> Result<Vec<u8>> {
        let _in = enter(&self.net);
        self.inner.get_option_in(level, name, input)
    }

    fn mmap(&self, offset: u64, len: usize) -> Result<crate::SocketMap> {
        self.inner.mmap(offset, len)
    }

    fn poll(&self) -> u32 {
        let _in = enter(&self.net);
        self.inner.poll()
    }

    // The wrapper adds the queues of the socket in it, so `poll`, `select` and `epoll_wait` wake
    // at a new event of the socket. Linux adds the queue in `sock_poll_wait`.
    fn poll_wait(&self, table: &mut PollTable) {
        self.inner.poll_wait(table);
    }

    fn event_count(&self) -> u64 {
        self.inner.event_count()
    }

    fn readable(&self) -> Result<usize> {
        let _in = enter(&self.net);
        self.inner.readable()
    }

    fn unsent(&self) -> Result<usize> {
        let _in = enter(&self.net);
        self.inner.unsent()
    }

    fn ioctl(&self, cmd: u32, arg: usize, mem: &dyn UserMemory) -> Option<Result<usize>> {
        let _in = enter(&self.net);
        self.inner.ioctl(cmd, arg, mem)
    }

    fn release(&self) {
        let _in = enter(&self.net);
        self.inner.release();
    }

    fn netns(&self) -> Option<&Arc<NetNs>> {
        Some(&self.net)
    }

    fn as_any(&self) -> &dyn Any {
        self.inner.as_any()
    }
}
