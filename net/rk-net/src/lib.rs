//! The socket layer: the operations of a socket, the file of a socket, and the options of the
//! level `SOL_SOCKET` that each family shares.
//!
//! A family gives a type that implements `Socket`. The system call layer makes a file with
//! `new_file`, and it finds the socket of a file with `socket_of`. The system call layer copies
//! the addresses, the data and the control messages between user memory and the kernel, thus a
//! family works only with kernel buffers. Linux has the same split in net/socket.c and the
//! `proto_ops` of each family.
//!
//! The crate also has the parts below the sockets that each protocol shares: the packet buffer
//! in `buf`, the network devices in `dev`, and the Ethernet and ARP formats.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod arp;
pub mod buf;
pub mod consts;
pub mod dev;
pub mod ether;
pub mod ioctl;
pub mod netlink;
pub mod ns;
mod options;
pub mod procfs;
pub mod sysctl;
pub mod veth;

pub use options::{Options, Timeout};

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicU64, Ordering};
use rk_abi::Errno;
use rk_abi::native::ioctls::{FIONREAD, TIOCOUTQ};
use rk_abi::native::open::O_RDWR;
use rk_abi::native::sockios::SIOCGIFCONF;
use rk_abi::native::stat::S_IFSOCK;
use rk_frame::sync::SpinLock;
use rk_vfs::inode::Result;
use rk_vfs::wait::PollTable;
use rk_vfs::wait::{WaitQueue, interrupted};
use rk_vfs::{File, FileOps, Metadata, UserMemory};

/// The credentials of a process, as `struct ucred` of Linux.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Cred {
    /// The ID of the process.
    pub pid: i32,
    /// The user ID.
    pub uid: u32,
    /// The group ID.
    pub gid: u32,
}

/// The credentials that `SO_PEERCRED` gives when the socket has no peer: no process, and the
/// overflow IDs of Linux.
pub const NO_CRED: Cred = Cred { pid: 0, uid: 65534, gid: 65534 };

static CRED_SOURCE: SpinLock<Option<fn() -> Cred>> = SpinLock::new(None);

/// Sets the function that gives the credentials of the current process. The process layer
/// calls this one time at boot.
pub fn set_cred_source(f: fn() -> Cred) {
    *CRED_SOURCE.lock() = Some(f);
}

/// The credentials of the current process.
pub fn current_cred() -> Cred {
    let source = *CRED_SOURCE.lock();
    source.map_or(Cred::default(), |f| f())
}

/// A message to send: the data, the address of the destination, and the contents of the
/// control messages.
#[derive(Default)]
pub struct Message {
    /// The data.
    pub data: Vec<u8>,
    /// The address of the destination, for `sendto` and `sendmsg`.
    pub addr: Option<Vec<u8>>,
    /// The files of `SCM_RIGHTS`.
    pub rights: Vec<Arc<File>>,
    /// The credentials of `SCM_CREDENTIALS`. Without them the message has the credentials of
    /// the sender.
    pub cred: Option<Cred>,
}

/// A message that a receive gives.
#[derive(Default)]
pub struct Received {
    /// The data, at most the size that the caller asked for.
    pub data: Vec<u8>,
    /// The size of the full datagram. It is more than `data.len()` if the receive truncated the
    /// datagram.
    pub len: usize,
    /// The address of the sender, if the sender has one.
    pub addr: Option<Vec<u8>>,
    /// The files of `SCM_RIGHTS`.
    pub rights: Vec<Arc<File>>,
    /// The credentials of the sender, if the receiver asked for them with `SO_PASSCRED`.
    pub cred: Option<Cred>,
    /// The flags for `msg_flags`: `MSG_TRUNC` and `MSG_EOR`.
    pub flags: u32,
    /// The control messages of the family, as `put_cmsg` of Linux: the level, the type and the
    /// data of each message, in order.
    pub control: Vec<(u32, u32, Vec<u8>)>,
}

/// The identity of a file in the tree, for a socket that has a path as its name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct NodeId {
    /// The device of the file system.
    pub dev: u64,
    /// The inode number.
    pub ino: u64,
}

/// The operations on the tree that a socket with a path name needs. The system call layer gives
/// them, because the walk uses the root and the current directory of the process.
pub trait PathOps {
    /// Makes the socket file `path` for `bind`. Gives `EADDRINUSE` if the name is in use.
    fn make_node(&self, path: &[u8]) -> Result<NodeId>;
    /// Finds the socket file `path` for `connect` and `sendto`.
    fn find_node(&self, path: &[u8]) -> Result<NodeId>;
}

/// The paths of a call that cannot have an address, as `write`.
pub struct NoPaths;

impl PathOps for NoPaths {
    fn make_node(&self, _path: &[u8]) -> Result<NodeId> {
        Err(Errno::EINVAL)
    }

    fn find_node(&self, _path: &[u8]) -> Result<NodeId> {
        Err(Errno::EINVAL)
    }
}

/// The operations of a socket. The default of each operation gives the error of Linux for a
/// family that does not have it.
pub trait Socket: Send + Sync {
    /// The family, as `AF_UNIX`.
    fn family(&self) -> u32;
    /// The type, as `SOCK_STREAM`.
    fn kind(&self) -> u32;
    /// The protocol.
    fn protocol(&self) -> u32 {
        0
    }
    /// The inode number of the socket file.
    fn ino(&self) -> u64;
    /// `bind`.
    fn bind(&self, _paths: &dyn PathOps, _addr: &[u8]) -> Result<()> {
        Err(Errno::EOPNOTSUPP)
    }
    /// `connect`.
    fn connect(&self, _paths: &dyn PathOps, _addr: &[u8], _nonblock: bool) -> Result<()> {
        Err(Errno::EOPNOTSUPP)
    }
    /// `listen`.
    fn listen(&self, _backlog: u32) -> Result<()> {
        Err(Errno::EOPNOTSUPP)
    }
    /// `accept`. Gives the new socket.
    fn accept(&self, _nonblock: bool) -> Result<Arc<dyn Socket>> {
        Err(Errno::EOPNOTSUPP)
    }
    /// Sends `msg`. Gives the count of bytes that the socket took.
    fn send(&self, paths: &dyn PathOps, msg: Message, flags: u32, nonblock: bool) -> Result<usize>;
    /// Receives at most `len` bytes.
    fn recv(&self, len: usize, flags: u32, nonblock: bool) -> Result<Received>;
    /// `shutdown`.
    fn shutdown(&self, _how: u32) -> Result<()> {
        Err(Errno::EOPNOTSUPP)
    }
    /// The address of the socket, for `getsockname`.
    fn name(&self) -> Vec<u8>;
    /// The address of the peer, for `getpeername`.
    fn peer_name(&self) -> Result<Vec<u8>> {
        Err(Errno::ENOTCONN)
    }
    /// `getsockopt`. Gives the value.
    fn get_option(&self, level: u32, name: u32) -> Result<Vec<u8>>;
    /// `setsockopt`.
    fn set_option(&self, level: u32, name: u32, value: &[u8]) -> Result<()>;
    /// The events of `poll`.
    fn poll(&self) -> u32;
    /// Adds to `table` the queues that a new event of the socket wakes, as `poll_wait` of Linux.
    /// A socket must add a queue, and wake it at each new event.
    fn poll_wait(&self, _table: &mut PollTable) {}
    /// A count that goes up at each wake of the socket, for an edge triggered epoll entry.
    fn event_count(&self) -> u64 {
        0
    }
    /// The count of bytes that a receive can take now, for `FIONREAD`.
    fn readable(&self) -> Result<usize> {
        Ok(0)
    }
    /// The count of bytes that the socket sent and the peer did not receive, for `TIOCOUTQ`.
    fn unsent(&self) -> Result<usize> {
        Ok(0)
    }
    /// The ioctls of the family, as the `ioctl` of `proto_ops` of Linux. Gives `None` for a call
    /// that the family does not take, as `ENOIOCTLCMD`: the socket file then tries the calls of
    /// the network devices.
    fn ioctl(&self, _cmd: u32, _arg: usize, _mem: &dyn UserMemory) -> Option<Result<usize>> {
        None
    }
    /// Closes the socket. The file calls this when it closes.
    fn release(&self) {}
    /// The network namespace of the socket, if the socket has one.
    fn netns(&self) -> Option<&Arc<ns::NetNs>> {
        None
    }
    /// The socket as `Any`, for the operations of one family.
    fn as_any(&self) -> &dyn Any;
}

/// Gives a new inode number for a socket file.
pub fn next_ino() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// The device of the socket files, as `sockfs` of Linux.
fn sock_dev() -> u64 {
    static DEV: AtomicU64 = AtomicU64::new(0);
    let dev = DEV.load(Ordering::Relaxed);
    if dev != 0 {
        return dev;
    }
    let new = rk_vfs::inode::anon_dev();
    match DEV.compare_exchange(0, new, Ordering::Relaxed, Ordering::Relaxed) {
        Ok(_) => new,
        Err(old) => old,
    }
}

/// The operations of the file of a socket.
struct SocketFile {
    socket: Arc<dyn Socket>,
}

impl Drop for SocketFile {
    fn drop(&mut self) {
        self.socket.release();
    }
}

impl FileOps for SocketFile {
    fn read(&self, file: &File, buf: &mut [u8]) -> Result<usize> {
        let r = self.socket.recv(buf.len(), 0, file.nonblock())?;
        buf[..r.data.len()].copy_from_slice(&r.data);
        Ok(r.data.len())
    }

    fn write(&self, file: &File, buf: &[u8]) -> Result<usize> {
        let msg = Message { data: buf.to_vec(), ..Message::default() };
        self.socket.send(&NoPaths, msg, 0, file.flags().nonblock())
    }

    fn ioctl(&self, _file: &File, cmd: u32, arg: usize, mem: &dyn UserMemory) -> Result<usize> {
        // The order of `sock_ioctl` and `sock_do_ioctl` of Linux: the list of the interfaces,
        // then the family, then the calls of the network devices. The calls of the devices use
        // the namespace of the socket.
        let _in = self.socket.netns().map(|n| ns::enter(n));
        if cmd == SIOCGIFCONF {
            return ioctl::ifconf(arg, mem);
        }
        if let Some(r) = self.socket.ioctl(cmd, arg, mem) {
            return r;
        }
        let n = match cmd {
            FIONREAD => self.socket.readable()?,
            TIOCOUTQ => self.socket.unsent()?,
            c if ioctl::is_socket_cmd(c) => return ioctl::dev_ioctl(cmd, arg, mem),
            _ => return Err(Errno::ENOTTY),
        };
        let n = i32::try_from(n).unwrap_or(i32::MAX);
        mem.write(arg, &n.to_ne_bytes())?;
        Ok(0)
    }

    fn pollable(&self) -> bool {
        true
    }

    fn poll_wait(&self, _file: &File, table: &mut PollTable) {
        self.socket.poll_wait(table);
    }

    fn poll(&self, _file: &File) -> u32 {
        self.socket.poll()
    }

    fn event_count(&self) -> u64 {
        self.socket.event_count()
    }

    fn metadata(&self) -> Option<Metadata> {
        Some(Metadata {
            dev: sock_dev(),
            ino: self.socket.ino(),
            mode: S_IFSOCK | 0o777,
            nlink: 1,
            blksize: 4096,
            ..Metadata::default()
        })
    }

    fn as_any(&self) -> Option<&dyn Any> {
        Some(self)
    }
}

/// Makes the file of `socket`. `flags` can hold `O_NONBLOCK`.
pub fn new_file(socket: Arc<dyn Socket>, flags: u32) -> Arc<File> {
    File::with_ops(Arc::new(SocketFile { socket }), None, O_RDWR | flags)
}

/// Gives the socket of `file`, or `None` if the file is not a socket.
pub fn socket_of(file: &File) -> Option<Arc<dyn Socket>> {
    let ops = file.ops().as_any()?.downcast_ref::<SocketFile>()?;
    Some(ops.socket.clone())
}

/// Blocks on `queue` until `cond` gives a value, a signal comes or the time `timeout` is over.
/// A signal gives `ERESTARTSYS` without a timeout and `EINTR` with one, as `sock_intr_errno` of
/// Linux. The end of the time gives `EAGAIN`.
///
/// # Errors
///
/// Gives the error of `cond`, `ERESTARTSYS`, `EINTR` or `EAGAIN`.
pub fn wait_for<R>(
    queue: &WaitQueue,
    timeout: Timeout,
    mut cond: impl FnMut() -> Result<Option<R>>,
) -> Result<R> {
    let Some(ticks) = timeout.ticks() else {
        return queue.wait_interruptible(cond);
    };
    let deadline = options::now().saturating_add(ticks);
    let r = queue.wait_until_timeout(deadline, || match cond() {
        Ok(Some(value)) => Some(Ok(value)),
        Err(e) => Some(Err(e)),
        Ok(None) if interrupted() => Some(Err(Errno::EINTR)),
        Ok(None) => None,
    });
    r.unwrap_or(Err(Errno::EAGAIN))
}

/// Serializes the host tests that change the global devices.
#[cfg(test)]
static TEST_DEVICES: rk_frame::sync::SpinLock<()> = rk_frame::sync::SpinLock::new(());

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_dev;
#[cfg(test)]
mod tests_ns;
