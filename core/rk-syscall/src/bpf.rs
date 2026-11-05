//! `bpf(2)`. The logic is in rk-bpf. This file gives it the memory, the files and the
//! credentials of the process.

use crate::cx::{Cx, SysResult};
use alloc::sync::Arc;
use rk_abi::Errno;
use rk_bpf::cgroup::{CgroupEnv, atype, bpf_prog_run_array_cg, cgroup_bpf_enabled};
use rk_bpf::inode::{BpfObj, bpf_mkobj, bpf_obj_of};
use rk_bpf::map::MapEnv;
use rk_bpf::prog::prog_type::BPF_PROG_TYPE_SOCKET_FILTER;
use rk_bpf::prog::{
    BpfCgroupDevCtx, BpfProg, BpfSock, BpfSockAddr, bpf_prog_of, run_socket_filter,
};
use rk_bpf::syscall::Env;
use rk_net::Socket;
use rk_net::filter::SkFilter;
use rk_vfs::file::File;

/// The pages of free memory that a new map leaves for the rest of the system.
const RESERVE_FRAMES: u64 = 1024;

struct BpfEnv<'a, 'b>(&'a Cx<'b>);

impl Env for BpfEnv<'_, '_> {
    fn copy_from_user(&self, addr: u64, buf: &mut [u8]) -> Result<(), Errno> {
        if buf.is_empty() {
            return Ok(());
        }
        self.0.vm()?.read(addr as usize, buf)
    }

    fn copy_to_user(&self, addr: u64, buf: &[u8]) -> Result<(), Errno> {
        if buf.is_empty() {
            return Ok(());
        }
        self.0.write_bytes(addr, buf)
    }

    fn capable(&self, cap: u32) -> bool {
        self.0.process().cred().capable(cap)
    }

    fn map_env(&self) -> MapEnv {
        MapEnv { nr_cpus: rk_frame::cpu::count(), cpu: rk_frame::cpu::id() }
    }

    fn avail_mem(&self) -> u64 {
        let free = rk_frame::mm::frame_stats().free as u64;
        free.saturating_sub(RESERVE_FRAMES) * 4096
    }

    fn fd_install(&self, file: Arc<File>) -> Result<i32, Errno> {
        self.0.files()?.lock().insert(file, true)
    }

    fn fdget(&self, fd: i32) -> Result<Arc<File>, Errno> {
        if fd < 0 {
            return Err(Errno::EBADF);
        }
        self.0.fdget(fd as u64)
    }

    fn obj_pin(&self, path_fd: i32, pathname: u64, obj: BpfObj) -> Result<(), Errno> {
        let path = self.0.read_path(pathname)?;
        let fs = self.0.fs()?;
        let start = self.0.dir_start(&fs, path_fd as u64, &path)?;
        fs.mkobj(&start, &path, 0o600, |dir, name, perm| bpf_mkobj(dir, name, perm, obj))?;
        Ok(())
    }

    fn obj_get(&self, path_fd: i32, pathname: u64, mask: u32) -> Result<BpfObj, Errno> {
        let path = self.0.read_path(pathname)?;
        let fs = self.0.fs()?;
        let start = self.0.dir_start(&fs, path_fd as u64, &path)?;
        let at = fs.resolve(&start, &path, true)?;
        fs.permission(&at, mask)?;
        bpf_obj_of(at.inode())
    }

    fn boot_ns(&self) -> u64 {
        crate::info::uptime_ns()
    }

    fn uid(&self) -> u32 {
        self.0.process().cred().uid
    }

    fn cgroup_get_from_fd(&self, fd: u32) -> Result<rk_cgroup::CgId, Errno> {
        let file = self.fdget(fd as i32)?;
        let inode = file.inode().ok_or(Errno::EBADF)?;
        rk_fs_cgroup::cgroup_of(inode).ok_or(Errno::EBADF)
    }

    fn cgroup_parent(&self, id: rk_cgroup::CgId) -> Option<rk_cgroup::CgId> {
        rk_cgroup::with(|h| h.parent(id))
    }

    fn cgroup_id(&self, id: rk_cgroup::CgId) -> u64 {
        rk_fs_cgroup::cgroup_ino(id)
    }
}

pub(crate) fn bpf(
    cx: &Cx<'_>,
    cmd: u64,
    uattr: u64,
    size: u64,
    uattr_common: u64,
    size_common: u64,
) -> SysResult {
    let r = rk_bpf::syscall::sys_bpf(
        &BpfEnv(cx),
        cmd as u32,
        uattr,
        size as u32,
        uattr_common,
        size_common as u32,
    )?;
    Ok(r as u64)
}

/// What the helpers of a program that filters packets see. The filter runs in the call that
/// sends the packet, so it does not give the task to the helpers.
struct FilterHelperEnv;

impl rk_bpf::helpers::HelperEnv for FilterHelperEnv {
    fn map_env(&self) -> MapEnv {
        MapEnv { nr_cpus: rk_frame::cpu::count(), cpu: rk_frame::cpu::id() }
    }

    fn ktime_get_ns(&self) -> u64 {
        crate::info::uptime_ns()
    }

    fn current_pid_tgid(&self) -> Option<u64> {
        None
    }

    fn current_uid_gid(&self) -> Option<u64> {
        None
    }

    fn current_cgroup_id(&self) -> u64 {
        0
    }
}

/// What the helpers of a cgroup program see: the current task, as the programs of Linux that
/// run in the call of the task.
struct TaskHelperEnv;

impl rk_bpf::helpers::HelperEnv for TaskHelperEnv {
    fn map_env(&self) -> MapEnv {
        MapEnv { nr_cpus: rk_frame::cpu::count(), cpu: rk_frame::cpu::id() }
    }

    fn ktime_get_ns(&self) -> u64 {
        crate::info::uptime_ns()
    }

    fn current_pid_tgid(&self) -> Option<u64> {
        let t = rk_proc::current_thread()?;
        Some(u64::from(t.process().pid()) << 32 | u64::from(t.tid()))
    }

    fn current_uid_gid(&self) -> Option<u64> {
        let cred = rk_proc::current_thread()?.process().cred();
        Some(u64::from(cred.gid) << 32 | u64::from(cred.uid))
    }

    fn current_cgroup_id(&self) -> u64 {
        rk_fs_cgroup::cgroup_ino(current_cgroup())
    }
}

/// The cgroup of the current task. A kernel thread is in the root cgroup.
fn current_cgroup() -> rk_cgroup::CgId {
    rk_proc::current_thread().map_or(rk_cgroup::ROOT, |t| t.process().cgroup())
}

/// The cgroup tree for the cgroup programs.
struct Cgroups;

impl CgroupEnv for Cgroups {
    fn cgroup_parent(&self, id: rk_cgroup::CgId) -> Option<rk_cgroup::CgId> {
        rk_cgroup::with(|h| h.parent(id))
    }

    fn cgroup_id(&self, id: rk_cgroup::CgId) -> u64 {
        rk_fs_cgroup::cgroup_ino(id)
    }
}

/// Runs the device programs of the cgroup of the current task, as
/// `__cgroup_bpf_check_dev_permission` of Linux. A program that gives 0 refuses the access with
/// `EPERM`.
fn cgroup_bpf_check_dev_permission(
    dev_type: u32,
    major: u32,
    minor: u32,
    access: u32,
) -> Result<(), Errno> {
    if !cgroup_bpf_enabled(atype::CGROUP_DEVICE) {
        return Ok(());
    }
    let mut ctx = BpfCgroupDevCtx { access_type: (access << 16) | dev_type, major, minor };
    bpf_prog_run_array_cg(&Cgroups, current_cgroup(), atype::CGROUP_DEVICE, |prog| {
        prog.run(&mut ctx, &TaskHelperEnv)
    })
}

/// Runs the programs of `BPF_CGROUP_INET_SOCK_CREATE` of the cgroup of the current task on a new
/// socket, as `BPF_CGROUP_RUN_PROG_INET_SOCK` in `inet_create` of Linux. A program that gives 0
/// refuses the socket with `EPERM`. The fields that a program writes go to the socket.
pub(crate) fn cgroup_run_inet_sock(sock: &dyn Socket) -> Result<(), Errno> {
    use rk_abi::native::socket::{SO_BINDTOIFINDEX, SO_MARK, SO_PRIORITY, SOL_SOCKET};
    if !cgroup_bpf_enabled(atype::CGROUP_INET_SOCK_CREATE) {
        return Ok(());
    }
    // A new socket is in the state `TCP_CLOSE`.
    let mut ctx = BpfSock {
        family: sock.family(),
        sock_type: sock.kind(),
        protocol: sock.protocol(),
        state: 7,
        ..BpfSock::default()
    };
    let atype = atype::CGROUP_INET_SOCK_CREATE;
    bpf_prog_run_array_cg(&Cgroups, current_cgroup(), atype, |prog| {
        prog.run(&mut ctx, &TaskHelperEnv)
    })?;
    for (name, value) in
        [(SO_BINDTOIFINDEX, ctx.bound_dev_if), (SO_MARK, ctx.mark), (SO_PRIORITY, ctx.priority)]
    {
        if value != 0 {
            let _ = sock.set_option(SOL_SOCKET, name, &value.to_ne_bytes());
        }
    }
    Ok(())
}

/// A program of `bind` gave a value with bit 1 set: the bind of a port below 1024 does not
/// need `CAP_NET_BIND_SERVICE`, `BPF_RET_BIND_NO_CAP_NET_BIND_SERVICE` of Linux.
pub(crate) const BIND_NO_CAP_NET_BIND_SERVICE: u32 = 1;

/// Runs the programs of `BPF_CGROUP_INET4_BIND`, `BPF_CGROUP_INET6_BIND`,
/// `BPF_CGROUP_INET4_CONNECT` or `BPF_CGROUP_INET6_CONNECT` of the cgroup of the current task
/// on the address of `bind` or `connect`, as `__cgroup_bpf_run_filter_sock_addr` of Linux. A
/// program can change the address and the port in `addr`. A program that gives 0 refuses the
/// call with `EPERM`. Gives the flags of the programs of `bind`.
pub(crate) fn cgroup_run_sock_addr(
    sock: &dyn Socket,
    addr: &mut [u8],
    connect: bool,
) -> Result<u32, Errno> {
    use rk_abi::native::inet::{IPPROTO_TCP, IPPROTO_UDP};
    use rk_net::consts::{AF_INET, AF_INET6};
    let family = sock.family();
    // `inet_bind_sk` and the `pre_connect` of TCP and UDP. A raw socket and a ping socket have
    // their own `bind` and no `pre_connect`.
    if !matches!(sock.protocol(), IPPROTO_TCP | IPPROTO_UDP) {
        return Ok(0);
    }
    let (atype, ip_off, ip_len, min_len) = match (family, connect) {
        (AF_INET, false) => (atype::CGROUP_INET4_BIND, 4, 4, 16),
        (AF_INET, true) => (atype::CGROUP_INET4_CONNECT, 4, 4, 16),
        // `SIN6_LEN_RFC2133`.
        (AF_INET6, false) => (atype::CGROUP_INET6_BIND, 8, 16, 24),
        (AF_INET6, true) => (atype::CGROUP_INET6_CONNECT, 8, 16, 24),
        _ => return Ok(0),
    };
    if !cgroup_bpf_enabled(atype) || addr.len() < min_len {
        return Ok(0);
    }
    let user_family = u32::from(u16::from_ne_bytes([addr[0], addr[1]]));
    // A `connect` to `AF_UNSPEC` disconnects the socket before the programs run.
    if connect && user_family == 0 {
        return Ok(0);
    }
    let mut ctx = BpfSockAddr {
        user_family,
        user_port: u32::from(u16::from_ne_bytes([addr[2], addr[3]])),
        family,
        sock_type: sock.kind(),
        protocol: sock.protocol(),
        ..BpfSockAddr::default()
    };
    ctx.user_ip[..ip_len].copy_from_slice(&addr[ip_off..ip_off + ip_len]);
    let mut flags = 0;
    bpf_prog_run_array_cg(&Cgroups, current_cgroup(), atype, |prog| {
        let ret = prog.run(&mut ctx, &TaskHelperEnv);
        flags |= (ret >> 1) as u32;
        ret & 1
    })?;
    addr[2..4].copy_from_slice(&(ctx.user_port as u16).to_ne_bytes());
    addr[ip_off..ip_off + ip_len].copy_from_slice(&ctx.user_ip[..ip_len]);
    Ok(if connect { 0 } else { flags & BIND_NO_CAP_NET_BIND_SERVICE })
}

/// Connects the hooks of the cgroup programs to the VFS. The boot code calls this one time.
pub(crate) fn init() {
    rk_vfs::device::set_devcgroup_check(cgroup_bpf_check_dev_permission);
    rk_net::filter::set_cgroup_skb_hooks(rk_net::filter::CgroupSkbHooks {
        current: current_cgroup,
        run: cgroup_bpf_run_filter_skb,
        enabled: |egress| {
            cgroup_bpf_enabled(if egress {
                atype::CGROUP_INET_EGRESS
            } else {
                atype::CGROUP_INET_INGRESS
            })
        },
    });
}

/// Runs the programs of `BPF_CGROUP_INET_INGRESS` or `BPF_CGROUP_INET_EGRESS` of `cgroup` on
/// `packet`, which starts at its IP header, as `__cgroup_bpf_run_filter_skb` of Linux. The
/// addresses and the ports of the socket come from the packet. Gives `false` if a program drops
/// the packet: a return value with the bit 0 clear. The congestion bit of the values 2 and 3
/// has no effect.
fn cgroup_bpf_run_filter_skb(cgroup: rk_cgroup::CgId, egress: bool, packet: &[u8]) -> bool {
    use rk_abi::native::if_ether::{ETH_P_IP, ETH_P_IPV6};
    use rk_net::consts::{AF_INET, AF_INET6};
    let atype = if egress { atype::CGROUP_INET_EGRESS } else { atype::CGROUP_INET_INGRESS };
    if !cgroup_bpf_enabled(atype) {
        return true;
    }
    let mut skb = rk_bpf::prog::SkBuff { data: packet, ..Default::default() };
    // The source and destination addresses, and the offset and protocol of the transport
    // header.
    let (src, dst, l4, proto) = match packet.first().map(|b| b >> 4) {
        Some(4) if packet.len() >= 20 => {
            skb.protocol = (ETH_P_IP as u16).to_be();
            skb.family = AF_INET;
            let (mut s, mut d) = ([0u8; 16], [0u8; 16]);
            s[..4].copy_from_slice(&packet[12..16]);
            d[..4].copy_from_slice(&packet[16..20]);
            (s, d, usize::from(packet[0] & 0xf) * 4, packet[9])
        }
        Some(6) if packet.len() >= 40 => {
            skb.protocol = (ETH_P_IPV6 as u16).to_be();
            skb.family = AF_INET6;
            let s: [u8; 16] = packet[8..24].try_into().unwrap_or_default();
            let d: [u8; 16] = packet[24..40].try_into().unwrap_or_default();
            (s, d, 40, packet[6])
        }
        _ => return true,
    };
    // The ports of TCP and UDP.
    let (sport, dport) = match packet.get(l4..l4 + 4) {
        Some(p) if matches!(proto, 6 | 17) => ([p[0], p[1]], [p[2], p[3]]),
        _ => ([0; 2], [0; 2]),
    };
    let (local, remote, lport, rport) =
        if egress { (src, dst, sport, dport) } else { (dst, src, dport, sport) };
    skb.local_ip = local;
    skb.remote_ip = remote;
    skb.local_port = u32::from(u16::from_be_bytes(lport));
    skb.remote_port = u32::from(u16::from_ne_bytes(rport));
    // A packet that comes in has no task, as the filter of a socket.
    let env: &dyn rk_bpf::helpers::HelperEnv =
        if egress { &TaskHelperEnv } else { &FilterHelperEnv };
    bpf_prog_run_array_cg(&Cgroups, cgroup, atype, |prog| prog.run(&mut skb, env)).is_ok()
}

/// A socket filter of `SO_ATTACH_BPF`.
struct BpfSkFilter(Arc<BpfProg>);

impl SkFilter for BpfSkFilter {
    fn run(&self, data: &[u8]) -> u32 {
        run_socket_filter(&self.0, data, 0, &FilterHelperEnv)
    }
}

/// The socket filter of the program file `ufd`, as `sk_attach_bpf` and `bpf_prog_get_type` of
/// Linux. A descriptor that is not a socket filter program gives `EINVAL`.
pub(crate) fn sk_filter_of(cx: &Cx<'_>, ufd: u32) -> Result<Arc<dyn SkFilter>, Errno> {
    let file = cx.fdget(u64::from(ufd))?;
    let prog = bpf_prog_of(&file).ok_or(Errno::EINVAL)?;
    if prog.prog_type != BPF_PROG_TYPE_SOCKET_FILTER {
        return Err(Errno::EINVAL);
    }
    Ok(Arc::new(BpfSkFilter(prog)))
}
