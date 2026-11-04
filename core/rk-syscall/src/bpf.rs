//! `bpf(2)`. The logic is in rk-bpf. This file gives it the memory, the files and the
//! credentials of the process.

use crate::cx::{Cx, SysResult};
use alloc::sync::Arc;
use rk_abi::Errno;
use rk_bpf::inode::{BpfObj, bpf_mkobj, bpf_obj_of};
use rk_bpf::map::MapEnv;
use rk_bpf::prog::prog_type::BPF_PROG_TYPE_SOCKET_FILTER;
use rk_bpf::prog::{BpfProg, bpf_prog_of, run_socket_filter};
use rk_bpf::syscall::Env;
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
