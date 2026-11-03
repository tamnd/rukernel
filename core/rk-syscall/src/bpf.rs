//! `bpf(2)`. The logic is in rk-bpf. This file gives it the memory, the files and the
//! credentials of the process.

use crate::cx::{Cx, SysResult};
use alloc::sync::Arc;
use rk_abi::Errno;
use rk_bpf::map::MapEnv;
use rk_bpf::syscall::Env;
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
