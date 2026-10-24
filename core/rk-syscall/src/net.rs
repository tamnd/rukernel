//! The system calls of sockets.
//!
//! These calls copy the addresses, the data and the control messages between user memory and
//! the kernel. The socket of the family does the work, as net/socket.c of Linux does it.

use crate::cx::{Cx, SysResult};
use crate::fs::read_iovecs;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_abi::native::at::AT_FDCWD;
use rk_abi::native::open::{O_CLOEXEC, O_NONBLOCK};
use rk_abi::native::signal::SIGPIPE;
use rk_abi::native::socket::SOL_SOCKET;
use rk_abi::native::types::Iovec;
use rk_net::consts::{
    AF_UNIX, MSG_CMSG_CLOEXEC, MSG_CTRUNC, MSG_NOSIGNAL, MSG_TRUNC, MSG_WAITFORONE,
    SCM_CREDENTIALS, SCM_MAX_FD, SCM_RIGHTS, SOCK_CLOEXEC, SOCK_NONBLOCK, SOCK_STREAM,
    SOCK_TYPE_MASK, SOMAXCONN,
};
use rk_net::{Cred, Message, NodeId, PathOps, Received, Socket};
use rk_net_unix::Unix;
use rk_proc::Pid;
use rk_proc::signal::{SI_USER, SigInfo};
use rk_vfs::File;
use rk_vfs::inode::mode::{S_IFMT, S_IFSOCK};

/// The size of `struct sockaddr_storage`, the longest address.
const SOCKADDR_MAX: usize = 128;
/// The size of `struct msghdr`.
const MSGHDR_SIZE: u64 = 56;
/// The size of `struct mmsghdr`: a `struct msghdr` and the count of bytes, with padding.
const MMSGHDR_SIZE: u64 = 64;
/// The size of `struct cmsghdr`.
const CMSGHDR_SIZE: usize = 16;
/// The size of `struct ucred`.
const UCRED_SIZE: usize = 12;
/// The most messages of `sendmmsg` and `recvmmsg`. Linux names it `UIO_MAXIOV`.
const MMSG_MAX: u64 = 1024;
/// The most bytes of one send. Linux names it `INT_MAX`.
const SEND_MAX: usize = i32::MAX as usize;
/// The most bytes of the value of `setsockopt` that the kernel reads.
const OPTION_MAX: usize = 4096;

/// The credentials of the current process, for the socket layer.
pub(crate) fn current_cred() -> Cred {
    let pid = rk_proc::current_thread().map_or(0, |t| t.process().pid() as i32);
    Cred { pid, uid: 0, gid: 0 }
}

/// The length of a control message with `len` bytes of data, as `CMSG_LEN`.
fn cmsg_len(len: usize) -> usize {
    CMSGHDR_SIZE + len
}

/// The space of a control message with `len` bytes of data, as `CMSG_SPACE`.
fn cmsg_space(len: usize) -> usize {
    CMSGHDR_SIZE + len.next_multiple_of(8)
}

/// The paths of the tree for a socket with a path name. The walk starts at the current
/// directory of the process.
struct Paths<'a, 'b> {
    cx: &'a Cx<'b>,
}

impl Paths<'_, '_> {
    fn node(at: &rk_vfs::Location) -> NodeId {
        let m = at.inode().metadata();
        NodeId { dev: m.dev, ino: m.ino }
    }
}

impl PathOps for Paths<'_, '_> {
    fn make_node(&self, path: &[u8]) -> Result<NodeId, Errno> {
        let fs = self.cx.fs()?;
        let start = self.cx.dir_start(&fs, AT_FDCWD as u64, path)?;
        match fs.mknod(&start, path, S_IFSOCK | 0o777, 0) {
            Ok(at) => Ok(Self::node(&at)),
            Err(Errno::EEXIST) => Err(Errno::EADDRINUSE),
            Err(e) => Err(e),
        }
    }

    fn find_node(&self, path: &[u8]) -> Result<NodeId, Errno> {
        let fs = self.cx.fs()?;
        let start = self.cx.dir_start(&fs, AT_FDCWD as u64, path)?;
        let at = fs.resolve(&start, path, true)?;
        if at.inode().metadata().mode & S_IFMT != S_IFSOCK {
            return Err(Errno::ECONNREFUSED);
        }
        Ok(Self::node(&at))
    }
}

/// The socket of `fd`. Gives `ENOTSOCK` if the file is not a socket.
fn socket(cx: &Cx<'_>, fd: u64) -> Result<(Arc<File>, Arc<dyn Socket>), Errno> {
    let file = cx.file(fd)?;
    let sock = rk_net::socket_of(&file).ok_or(Errno::ENOTSOCK)?;
    Ok((file, sock))
}

/// Gives the type and the flags of the argument `type` of `socket`.
fn split_type(kind: u64) -> Result<(u32, u32), Errno> {
    let kind = u32::try_from(kind).map_err(|_| Errno::EINVAL)?;
    let flags = kind & !SOCK_TYPE_MASK;
    if flags & !(SOCK_CLOEXEC | SOCK_NONBLOCK) != 0 {
        return Err(Errno::EINVAL);
    }
    Ok((kind & SOCK_TYPE_MASK, flags))
}

/// Makes a socket of the family `domain`.
fn new_socket(domain: u64, kind: u32, protocol: u64) -> Result<Arc<Unix>, Errno> {
    if domain != u64::from(AF_UNIX) {
        return Err(Errno::EAFNOSUPPORT);
    }
    rk_net_unix::check_protocol(u32::try_from(protocol).map_err(|_| Errno::EPROTONOSUPPORT)?)?;
    Unix::new(kind)
}

/// Adds the file of `sock` to the descriptor table.
fn install(cx: &Cx<'_>, sock: Arc<dyn Socket>, flags: u32) -> Result<i32, Errno> {
    let file = rk_net::new_file(sock, flags & O_NONBLOCK);
    cx.files()?.lock().insert(file, flags & O_CLOEXEC != 0)
}

pub(crate) fn socket_call(cx: &Cx<'_>, domain: u64, kind: u64, protocol: u64) -> SysResult {
    let (kind, flags) = split_type(kind)?;
    let sock = new_socket(domain, kind, protocol)?;
    Ok(install(cx, sock, flags)? as u64)
}

pub(crate) fn socketpair(cx: &Cx<'_>, domain: u64, kind: u64, protocol: u64, sv: u64) -> SysResult {
    let (kind, flags) = split_type(kind)?;
    if domain != u64::from(AF_UNIX) {
        return Err(Errno::EAFNOSUPPORT);
    }
    rk_net_unix::check_protocol(u32::try_from(protocol).map_err(|_| Errno::EPROTONOSUPPORT)?)?;
    let (a, b) = Unix::pair(kind)?;
    let fa = rk_net::new_file(a, flags & O_NONBLOCK);
    let fb = rk_net::new_file(b, flags & O_NONBLOCK);
    let cloexec = flags & O_CLOEXEC != 0;
    let files = cx.files()?;
    let mut table = files.lock();
    let x = table.insert(fa, cloexec)?;
    let y = match table.insert(fb, cloexec) {
        Ok(y) => y,
        Err(e) => {
            let _ = table.remove(x);
            return Err(e);
        }
    };
    drop(table);
    let mut fds = [0u8; 8];
    fds[..4].copy_from_slice(&x.to_ne_bytes());
    fds[4..].copy_from_slice(&y.to_ne_bytes());
    if let Err(e) = cx.write_bytes(sv, &fds) {
        let mut table = files.lock();
        let _ = table.remove(x);
        let _ = table.remove(y);
        return Err(e);
    }
    Ok(0)
}

/// Reads an address of `len` bytes from user memory, as `move_addr_to_kernel` of Linux.
fn read_addr(cx: &Cx<'_>, addr: u64, len: u64) -> Result<Vec<u8>, Errno> {
    let len = len as u32 as usize;
    if len > SOCKADDR_MAX {
        return Err(Errno::EINVAL);
    }
    if len == 0 {
        return Ok(Vec::new());
    }
    cx.read_bytes(addr, len)
}

/// Writes the address `value` to user memory, as `move_addr_to_user` of Linux. `lenp` holds
/// the size of the buffer, and gets the size of the address.
fn write_addr(cx: &Cx<'_>, addr: u64, lenp: u64, value: &[u8]) -> Result<(), Errno> {
    let len: i32 = cx.read_val(lenp)?;
    let len = usize::try_from(len).map_err(|_| Errno::EINVAL)?;
    let n = len.min(value.len());
    if n > 0 {
        cx.write_bytes(addr, &value[..n])?;
    }
    cx.write_val(lenp, &(value.len() as i32))
}

pub(crate) fn bind(cx: &Cx<'_>, fd: u64, addr: u64, len: u64) -> SysResult {
    let (_, sock) = socket(cx, fd)?;
    let addr = read_addr(cx, addr, len)?;
    sock.bind(&Paths { cx }, &addr)?;
    Ok(0)
}

pub(crate) fn connect(cx: &Cx<'_>, fd: u64, addr: u64, len: u64) -> SysResult {
    let (file, sock) = socket(cx, fd)?;
    let addr = read_addr(cx, addr, len)?;
    sock.connect(&Paths { cx }, &addr, file.flags().nonblock())?;
    Ok(0)
}

pub(crate) fn listen(cx: &Cx<'_>, fd: u64, backlog: u64) -> SysResult {
    let (_, sock) = socket(cx, fd)?;
    sock.listen((backlog as u32).min(SOMAXCONN))?;
    Ok(0)
}

pub(crate) fn accept4(cx: &Cx<'_>, fd: u64, addr: u64, lenp: u64, flags: u64) -> SysResult {
    let flags = u32::try_from(flags).map_err(|_| Errno::EINVAL)?;
    if flags & !(SOCK_CLOEXEC | SOCK_NONBLOCK) != 0 {
        return Err(Errno::EINVAL);
    }
    let (file, sock) = socket(cx, fd)?;
    let new = sock.accept(file.flags().nonblock())?;
    let peer = new.peer_name().unwrap_or_else(|_| (AF_UNIX as u16).to_ne_bytes().to_vec());
    let new_fd = install(cx, new, flags)?;
    if addr != 0
        && let Err(e) = write_addr(cx, addr, lenp, &peer)
    {
        let _ = cx.files()?.lock().remove(new_fd);
        return Err(e);
    }
    Ok(new_fd as u64)
}

pub(crate) fn getsockname(cx: &Cx<'_>, fd: u64, addr: u64, lenp: u64) -> SysResult {
    let (_, sock) = socket(cx, fd)?;
    write_addr(cx, addr, lenp, &sock.name())?;
    Ok(0)
}

pub(crate) fn getpeername(cx: &Cx<'_>, fd: u64, addr: u64, lenp: u64) -> SysResult {
    let (_, sock) = socket(cx, fd)?;
    write_addr(cx, addr, lenp, &sock.peer_name()?)?;
    Ok(0)
}

pub(crate) fn shutdown(cx: &Cx<'_>, fd: u64, how: u64) -> SysResult {
    let (_, sock) = socket(cx, fd)?;
    sock.shutdown(u32::try_from(how).map_err(|_| Errno::EINVAL)?)?;
    Ok(0)
}

pub(crate) fn getsockopt(
    cx: &Cx<'_>,
    fd: u64,
    level: u64,
    name: u64,
    value: u64,
    lenp: u64,
) -> SysResult {
    let (_, sock) = socket(cx, fd)?;
    let len: i32 = cx.read_val(lenp)?;
    let len = usize::try_from(len).map_err(|_| Errno::EINVAL)?;
    let v = sock.get_option(level as u32, name as u32)?;
    let n = len.min(v.len());
    if n > 0 {
        cx.write_bytes(value, &v[..n])?;
    }
    cx.write_val(lenp, &(n as i32))?;
    Ok(0)
}

pub(crate) fn setsockopt(
    cx: &Cx<'_>,
    fd: u64,
    level: u64,
    name: u64,
    value: u64,
    len: u64,
) -> SysResult {
    let (_, sock) = socket(cx, fd)?;
    let len = usize::try_from(len as i32).map_err(|_| Errno::EINVAL)?;
    let v = if len == 0 { Vec::new() } else { cx.read_bytes(value, len.min(OPTION_MAX))? };
    sock.set_option(level as u32, name as u32, &v)?;
    Ok(0)
}

/// Sends `SIGPIPE` for `EPIPE`, unless the flags have `MSG_NOSIGNAL`.
fn sigpipe(cx: &Cx<'_>, flags: u32, r: SysResult) -> SysResult {
    if r == Err(Errno::EPIPE) && flags & MSG_NOSIGNAL == 0 {
        let pid = cx.process().pid();
        cx.thread.send_signal(SigInfo::new(SIGPIPE, SI_USER, pid));
    }
    r
}

/// Reads the data of the vectors `iovs` from user memory.
fn gather(cx: &Cx<'_>, iovs: &[Iovec]) -> Result<Vec<u8>, Errno> {
    let total = iovs.iter().fold(0usize, |t, v| t.saturating_add(v.iov_len as usize));
    let mut data = Vec::with_capacity(total.min(SEND_MAX).min(1 << 20));
    for v in iovs {
        let n = (v.iov_len as usize).min(SEND_MAX - data.len());
        if n == 0 {
            continue;
        }
        data.extend_from_slice(&cx.read_bytes(v.iov_base, n)?);
    }
    Ok(data)
}

/// Writes `data` to the vectors `iovs` in user memory.
fn scatter(cx: &Cx<'_>, iovs: &[Iovec], data: &[u8]) -> Result<(), Errno> {
    let mut done = 0;
    for v in iovs {
        if done == data.len() {
            break;
        }
        let n = (v.iov_len as usize).min(data.len() - done);
        if n > 0 {
            cx.write_bytes(v.iov_base, &data[done..done + n])?;
        }
        done += n;
    }
    Ok(())
}

/// Sends the bytes of `msg` on `sock`.
fn send(cx: &Cx<'_>, file: &File, sock: &dyn Socket, msg: Message, flags: u32) -> SysResult {
    let r = sock.send(&Paths { cx }, msg, flags, file.flags().nonblock()).map(|n| n as u64);
    sigpipe(cx, flags, r)
}

pub(crate) fn sendto(
    cx: &Cx<'_>,
    fd: u64,
    buf: u64,
    len: u64,
    flags: u64,
    addr: u64,
    addrlen: u64,
) -> SysResult {
    let flags = flags as u32;
    let (file, sock) = socket(cx, fd)?;
    let len = (len as usize).min(SEND_MAX);
    let data = if len == 0 { Vec::new() } else { cx.read_bytes(buf, len)? };
    let addr = if addr == 0 { Vec::new() } else { read_addr(cx, addr, addrlen)? };
    let msg = Message { data, addr: (!addr.is_empty()).then_some(addr), ..Message::default() };
    send(cx, &file, &*sock, msg, flags)
}

pub(crate) fn recvfrom(
    cx: &Cx<'_>,
    fd: u64,
    buf: u64,
    len: u64,
    flags: u64,
    addr: u64,
    lenp: u64,
) -> SysResult {
    let flags = flags as u32;
    let (file, sock) = socket(cx, fd)?;
    let len = (len as usize).min(SEND_MAX);
    let r = sock.recv(len, flags & !MSG_CMSG_CLOEXEC, file.flags().nonblock())?;
    if !r.data.is_empty() {
        cx.write_bytes(buf, &r.data)?;
    }
    if addr != 0 && lenp != 0 {
        write_addr(cx, addr, lenp, r.addr.as_deref().unwrap_or(&[]))?;
    }
    Ok(result_len(&*sock, &r, flags))
}

/// The value of a receive: the full size of a datagram for `MSG_TRUNC`, as Linux.
fn result_len(sock: &dyn Socket, r: &Received, flags: u32) -> u64 {
    if flags & MSG_TRUNC != 0 && sock.kind() != SOCK_STREAM {
        r.len as u64
    } else {
        r.data.len() as u64
    }
}

/// A `struct msghdr` in user memory.
struct MsgHdr {
    name: u64,
    namelen: u32,
    iov: u64,
    iovlen: u64,
    control: u64,
    controllen: u64,
}

impl MsgHdr {
    fn read(cx: &Cx<'_>, addr: u64) -> Result<Self, Errno> {
        let b = cx.read_bytes(addr, MSGHDR_SIZE as usize)?;
        let word = |i: usize| {
            let mut w = [0u8; 8];
            w.copy_from_slice(&b[i..i + 8]);
            u64::from_ne_bytes(w)
        };
        Ok(Self {
            name: word(0),
            namelen: word(8) as u32,
            iov: word(16),
            iovlen: word(24),
            control: word(32),
            controllen: word(40),
        })
    }
}

/// Reads the control messages of a send, as `__scm_send` of Linux.
fn read_control(cx: &Cx<'_>, hdr: &MsgHdr, msg: &mut Message) -> Result<(), Errno> {
    if hdr.controllen == 0 {
        return Ok(());
    }
    if hdr.controllen > i32::MAX as u64 {
        return Err(Errno::ENOBUFS);
    }
    let buf = cx.read_bytes(hdr.control, hdr.controllen as usize)?;
    let files = cx.files()?;
    let mut off = 0;
    while off + CMSGHDR_SIZE <= buf.len() {
        let mut w = [0u8; 8];
        w.copy_from_slice(&buf[off..off + 8]);
        let len = u64::from_ne_bytes(w) as usize;
        if len < CMSGHDR_SIZE || len > buf.len() - off {
            return Err(Errno::EINVAL);
        }
        let mut l = [0u8; 4];
        l.copy_from_slice(&buf[off + 8..off + 12]);
        let level = u32::from_ne_bytes(l);
        l.copy_from_slice(&buf[off + 12..off + 16]);
        let kind = u32::from_ne_bytes(l);
        let data = &buf[off + CMSGHDR_SIZE..off + len];
        if level == SOL_SOCKET {
            match kind {
                SCM_RIGHTS => {
                    let (fds, _) = data.as_chunks::<4>();
                    if msg.rights.len() + fds.len() > SCM_MAX_FD {
                        return Err(Errno::EINVAL);
                    }
                    let table = files.lock();
                    for fd in fds {
                        msg.rights.push(table.file(i32::from_ne_bytes(*fd))?);
                    }
                }
                SCM_CREDENTIALS => {
                    if len != cmsg_len(UCRED_SIZE) {
                        return Err(Errno::EINVAL);
                    }
                    let (words, _) = data.as_chunks::<4>();
                    let pid = i32::from_ne_bytes(words[0]);
                    let uid = u32::from_ne_bytes(words[1]);
                    let gid = u32::from_ne_bytes(words[2]);
                    if uid == u32::MAX || gid == u32::MAX {
                        return Err(Errno::EINVAL);
                    }
                    if rk_proc::find_process(pid as Pid).is_none() {
                        return Err(Errno::ESRCH);
                    }
                    msg.cred = Some(Cred { pid, uid, gid });
                }
                _ => return Err(Errno::EINVAL),
            }
        }
        off += len.next_multiple_of(8);
    }
    Ok(())
}

/// Writes the control messages of a receive, as `put_cmsg` and `scm_detach_fds` of Linux.
/// Gives the bytes of the control buffer that the messages use and the flag `MSG_CTRUNC`.
fn write_control(cx: &Cx<'_>, hdr: &MsgHdr, r: Received, flags: u32) -> Result<(u64, u32), Errno> {
    let mut space = if hdr.control == 0 { 0 } else { hdr.controllen as usize };
    let mut out: Vec<u8> = Vec::new();
    let mut ctrunc = 0;
    let put = |out: &mut Vec<u8>, space: &mut usize, kind: u32, data: &[u8]| -> bool {
        if *space < CMSGHDR_SIZE {
            return false;
        }
        let mut len = cmsg_len(data.len());
        let full = *space >= len;
        len = len.min(*space);
        let mut m = vec![0u8; len];
        m[..8].copy_from_slice(&(len as u64).to_ne_bytes());
        m[8..12].copy_from_slice(&SOL_SOCKET.to_ne_bytes());
        m[12..16].copy_from_slice(&kind.to_ne_bytes());
        m[CMSGHDR_SIZE..].copy_from_slice(&data[..len - CMSGHDR_SIZE]);
        out.extend_from_slice(&m);
        let step = cmsg_space(data.len()).min(*space);
        out.resize(out.len() + step - len, 0);
        *space -= step;
        full
    };
    if let Some(c) = r.cred {
        let mut v = Vec::with_capacity(UCRED_SIZE);
        v.extend_from_slice(&c.pid.to_ne_bytes());
        v.extend_from_slice(&c.uid.to_ne_bytes());
        v.extend_from_slice(&c.gid.to_ne_bytes());
        if !put(&mut out, &mut space, SCM_CREDENTIALS, &v) {
            ctrunc = MSG_CTRUNC;
        }
    }
    if !r.rights.is_empty() {
        let max = space.saturating_sub(CMSGHDR_SIZE) / 4;
        let mut fds = Vec::new();
        let files = cx.files()?;
        let mut table = files.lock();
        for file in r.rights.iter().take(max) {
            match table.insert(file.clone(), flags & MSG_CMSG_CLOEXEC != 0) {
                Ok(fd) => fds.extend_from_slice(&fd.to_ne_bytes()),
                Err(_) => break,
            }
        }
        drop(table);
        if fds.len() / 4 < r.rights.len() {
            ctrunc = MSG_CTRUNC;
        }
        if !fds.is_empty() {
            put(&mut out, &mut space, SCM_RIGHTS, &fds);
        }
    }
    if !out.is_empty() {
        cx.write_bytes(hdr.control, &out)?;
    }
    Ok((out.len() as u64, ctrunc))
}

/// Sends one `struct msghdr`.
fn sendmsg_one(cx: &Cx<'_>, file: &File, sock: &dyn Socket, addr: u64, flags: u32) -> SysResult {
    let hdr = MsgHdr::read(cx, addr)?;
    let iovs = read_iovecs(cx, hdr.iov, hdr.iovlen)?;
    let mut msg = Message { data: gather(cx, &iovs)?, ..Message::default() };
    if hdr.name != 0 && hdr.namelen != 0 {
        msg.addr = Some(read_addr(cx, hdr.name, u64::from(hdr.namelen))?);
    }
    read_control(cx, &hdr, &mut msg)?;
    send(cx, file, sock, msg, flags)
}

/// Receives one `struct msghdr`.
fn recvmsg_one(
    cx: &Cx<'_>,
    file: &File,
    sock: &dyn Socket,
    addr: u64,
    flags: u32,
    nonblock: bool,
) -> SysResult {
    let hdr = MsgHdr::read(cx, addr)?;
    let iovs = read_iovecs(cx, hdr.iov, hdr.iovlen)?;
    let len = iovs.iter().fold(0usize, |t, v| t.saturating_add(v.iov_len as usize));
    let nonblock = nonblock || file.flags().nonblock();
    let r = sock.recv(len.min(SEND_MAX), flags & !MSG_CMSG_CLOEXEC, nonblock)?;
    scatter(cx, &iovs, &r.data)?;
    let n = result_len(sock, &r, flags);
    if hdr.name != 0 {
        let from = r.addr.clone().unwrap_or_default();
        let room = (hdr.namelen as usize).min(from.len());
        if room > 0 {
            cx.write_bytes(hdr.name, &from[..room])?;
        }
        cx.write_val(addr + 8, &(from.len() as u32))?;
    }
    let msg_flags = r.flags;
    let (used, ctrunc) = write_control(cx, &hdr, r, flags)?;
    cx.write_val(addr + 40, &used)?;
    cx.write_val(addr + 48, &(msg_flags | ctrunc))?;
    Ok(n)
}

pub(crate) fn sendmsg(cx: &Cx<'_>, fd: u64, msg: u64, flags: u64) -> SysResult {
    let (file, sock) = socket(cx, fd)?;
    sendmsg_one(cx, &file, &*sock, msg, flags as u32)
}

pub(crate) fn recvmsg(cx: &Cx<'_>, fd: u64, msg: u64, flags: u64) -> SysResult {
    let (file, sock) = socket(cx, fd)?;
    recvmsg_one(cx, &file, &*sock, msg, flags as u32, false)
}

pub(crate) fn sendmmsg(cx: &Cx<'_>, fd: u64, vec: u64, vlen: u64, flags: u64) -> SysResult {
    let (file, sock) = socket(cx, fd)?;
    let vlen = (vlen as u32 as u64).min(MMSG_MAX);
    let mut done = 0;
    while done < vlen {
        let at = vec + done * MMSGHDR_SIZE;
        match sendmsg_one(cx, &file, &*sock, at, flags as u32) {
            Ok(n) => cx.write_val(at + MSGHDR_SIZE, &(n as u32))?,
            Err(e) if done == 0 => return Err(e),
            Err(_) => break,
        }
        done += 1;
    }
    Ok(done)
}

pub(crate) fn recvmmsg(
    cx: &Cx<'_>,
    fd: u64,
    vec: u64,
    vlen: u64,
    flags: u64,
    timeout: u64,
) -> SysResult {
    let (file, sock) = socket(cx, fd)?;
    if timeout != 0 {
        let t: rk_abi::native::types::KernelTimespec = cx.read_val(timeout)?;
        if t.tv_sec < 0 || !(0..1_000_000_000).contains(&t.tv_nsec) {
            return Err(Errno::EINVAL);
        }
    }
    let flags = flags as u32;
    let vlen = (vlen as u32 as u64).min(MMSG_MAX);
    let mut done = 0;
    while done < vlen {
        let at = vec + done * MMSGHDR_SIZE;
        let nonblock = done > 0 && flags & MSG_WAITFORONE != 0;
        match recvmsg_one(cx, &file, &*sock, at, flags & !MSG_WAITFORONE, nonblock) {
            Ok(n) => cx.write_val(at + MSGHDR_SIZE, &(n as u32))?,
            Err(e) if done == 0 => return Err(e),
            Err(_) => break,
        }
        done += 1;
    }
    Ok(done)
}

/// `read` and `readv` on a socket: one receive into the vectors, as `sock_read_iter` of Linux.
pub(crate) fn read_socket(
    cx: &Cx<'_>,
    file: &File,
    sock: &dyn Socket,
    iovs: &[Iovec],
) -> SysResult {
    let len = iovs.iter().fold(0usize, |t, v| t.saturating_add(v.iov_len as usize));
    if len == 0 {
        return Ok(0);
    }
    let r = sock.recv(len.min(SEND_MAX), 0, file.flags().nonblock())?;
    scatter(cx, iovs, &r.data)?;
    Ok(r.data.len() as u64)
}

/// `write` and `writev` on a socket: one send of the vectors, as `sock_write_iter` of Linux.
pub(crate) fn write_socket(
    cx: &Cx<'_>,
    file: &File,
    sock: &dyn Socket,
    iovs: &[Iovec],
) -> SysResult {
    let data = gather(cx, iovs)?;
    if data.is_empty() && sock.kind() == SOCK_STREAM {
        return Ok(0);
    }
    send(cx, file, sock, Message { data, ..Message::default() }, 0)
}
