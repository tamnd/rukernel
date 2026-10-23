//! The context of one system call, and the copies to and from user memory.

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_frame::user::UserContext;
use rk_mm::AddressSpace;
use rk_proc::stack::{ARG_MAX, MAX_ARG_STRLEN};
use rk_proc::{Process, SharedFiles, SharedFs, Thread, WaitStatus};
use rk_vfs::{File, FsContext, Location, UserMemory};
use zerocopy::{FromBytes, Immutable, IntoBytes};

/// The result of a handler: the return value, or an error.
pub(crate) type SysResult = Result<u64, Errno>;

/// The longest path, with its zero byte. Linux names it `PATH_MAX`.
pub(crate) const PATH_MAX: usize = 4096;

/// The most arguments or environment strings of `execve`. Linux names it `MAX_ARG_STRINGS`.
const MAX_ARG_STRINGS: usize = 0x7fff_ffff;

/// The thread that made the system call and its registers.
pub(crate) struct Cx<'a> {
    pub(crate) thread: &'a Arc<Thread>,
    pub(crate) regs: &'a mut UserContext,
    /// The status of the thread if the system call ends it.
    pub(crate) exit: Option<WaitStatus>,
}

/// The user memory of an address space, for the `ioctl` of a file.
pub(crate) struct UserMem<'a>(pub &'a AddressSpace);

impl UserMemory for UserMem<'_> {
    fn read(&self, addr: usize, buf: &mut [u8]) -> Result<(), Errno> {
        self.0.read(addr, buf)
    }

    fn write(&self, addr: usize, buf: &[u8]) -> Result<(), Errno> {
        self.0.write(addr, buf)
    }
}

impl Cx<'_> {
    /// The process of the thread.
    pub(crate) fn process(&self) -> &Arc<Process> {
        self.thread.process()
    }

    /// The address space.
    pub(crate) fn vm(&self) -> Result<Arc<AddressSpace>, Errno> {
        self.process().vm().ok_or(Errno::ESRCH)
    }

    /// The descriptor table.
    pub(crate) fn files(&self) -> Result<SharedFiles, Errno> {
        self.process().files().ok_or(Errno::ESRCH)
    }

    /// The file system context.
    pub(crate) fn fs_shared(&self) -> Result<SharedFs, Errno> {
        self.process().fs().ok_or(Errno::ESRCH)
    }

    /// A copy of the file system context. A walk uses a copy, so that a walk that blocks does not
    /// hold the lock.
    pub(crate) fn fs(&self) -> Result<FsContext, Errno> {
        Ok(self.fs_shared()?.lock().clone())
    }

    /// The open file of `fd`.
    pub(crate) fn file(&self, fd: u64) -> Result<Arc<File>, Errno> {
        self.files()?.lock().file(fd as i32)
    }

    /// The start of a walk for the `*at` calls: the current directory for `AT_FDCWD`, or the
    /// directory of `dirfd`. The path is not examined, so the caller gives an absolute path to
    /// skip the check of `dirfd`.
    pub(crate) fn dir_start(
        &self,
        fs: &FsContext,
        dirfd: u64,
        path: &[u8],
    ) -> Result<Location, Errno> {
        let dirfd = dirfd as i32;
        if dirfd == rk_abi::native::at::AT_FDCWD || path.first() == Some(&b'/') {
            return Ok(fs.cwd().clone());
        }
        let file = self.files()?.lock().file(dirfd)?;
        let at = file.location().ok_or(Errno::ENOTDIR)?.clone();
        if !path.is_empty() && !at.inode().metadata().is_dir() {
            return Err(Errno::ENOTDIR);
        }
        Ok(at)
    }

    /// Reads a value from user memory.
    pub(crate) fn read_val<T: FromBytes + IntoBytes>(&self, addr: u64) -> Result<T, Errno> {
        let mut v = T::new_zeroed();
        self.vm()?.read(addr as usize, v.as_mut_bytes())?;
        Ok(v)
    }

    /// Writes a value to user memory.
    pub(crate) fn write_val<T: IntoBytes + Immutable>(
        &self,
        addr: u64,
        value: &T,
    ) -> Result<(), Errno> {
        self.vm()?.write(addr as usize, value.as_bytes())
    }

    /// Writes a value to user memory if `addr` is not 0.
    pub(crate) fn write_opt<T: IntoBytes + Immutable>(
        &self,
        addr: u64,
        value: &T,
    ) -> Result<(), Errno> {
        if addr == 0 { Ok(()) } else { self.write_val(addr, value) }
    }

    /// Reads `len` bytes from user memory.
    pub(crate) fn read_bytes(&self, addr: u64, len: usize) -> Result<Vec<u8>, Errno> {
        let mut buf = vec![0u8; len];
        self.vm()?.read(addr as usize, &mut buf)?;
        Ok(buf)
    }

    /// Writes bytes to user memory.
    pub(crate) fn write_bytes(&self, addr: u64, buf: &[u8]) -> Result<(), Errno> {
        self.vm()?.write(addr as usize, buf)
    }

    /// Reads a path. Gives `ENOENT` for an empty path, as Linux, unless `empty_ok`.
    pub(crate) fn read_path_opt(&self, addr: u64, empty_ok: bool) -> Result<Vec<u8>, Errno> {
        let path = self.vm()?.read_cstr(addr as usize, PATH_MAX)?;
        if path.is_empty() && !empty_ok {
            return Err(Errno::ENOENT);
        }
        Ok(path)
    }

    /// Reads a path that must not be empty.
    pub(crate) fn read_path(&self, addr: u64) -> Result<Vec<u8>, Errno> {
        self.read_path_opt(addr, false)
    }

    /// Reads an array of string pointers that ends with a null pointer, for `execve`. A null
    /// array is empty, as Linux takes it. `total` counts the bytes of the strings and the
    /// pointers, for the `ARG_MAX` limit.
    pub(crate) fn read_strings(&self, addr: u64, total: &mut usize) -> Result<Vec<Vec<u8>>, Errno> {
        let mut out = Vec::new();
        if addr == 0 {
            return Ok(out);
        }
        let vm = self.vm()?;
        for i in 0..MAX_ARG_STRINGS {
            let mut ptr = [0u8; 8];
            vm.read(addr as usize + i * 8, &mut ptr)?;
            let ptr = u64::from_ne_bytes(ptr);
            if ptr == 0 {
                break;
            }
            let s = vm
                .read_cstr(ptr as usize, MAX_ARG_STRLEN)
                .map_err(|e| if e == Errno::ENAMETOOLONG { Errno::E2BIG } else { e })?;
            *total += s.len() + 1 + 8;
            if *total > ARG_MAX {
                return Err(Errno::E2BIG);
            }
            out.push(s);
        }
        Ok(out)
    }
}
