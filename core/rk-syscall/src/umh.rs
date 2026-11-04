//! The user mode helper, as kernel/umh.c of Linux: the kernel starts a program as a new process
//! and waits for its end. The upcall of `request_key` runs `/sbin/request-key` with it.
//!
//! The helper is a process of its own with no parent, as a child of kthreadd in Linux: it has
//! the credentials of root, the file system context of the boot, no open file, and the process
//! group and session 0. A new kernel task does the `execve`, as
//! `call_usermodehelper_exec_async`, so the address space of the caller stays. The caller waits
//! for the end of the helper, as `UMH_WAIT_PROC`, and the process goes away at its end.

use crate::run::{random16, run};
use alloc::sync::Arc;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_frame::addr::VirtAddr;
use rk_frame::sync::SpinLock;
use rk_frame::task::TaskOptions;
use rk_frame::user::UserContext;
use rk_proc::exec::{ExecArgs, exec};
use rk_proc::{Thread, WaitStatus};
use rk_vfs::FsContext;

/// The file system context of the helpers: the root and the current directory of the boot, as
/// `init_fs` of Linux.
static FS: SpinLock<Option<FsContext>> = SpinLock::new(None);

/// Keeps the file system context of the boot for the helpers.
pub(crate) fn set_fs(fs: &FsContext) {
    *FS.lock() = Some(fs.clone());
}

/// Runs the program at `path` with `argv` and `envp` as a helper and waits for its end, as
/// `call_usermodehelper_exec` with `UMH_WAIT_PROC`. `setup` changes the thread of the helper
/// before the `execve`, as the `init` function of `struct subprocess_info`. Gives the status
/// of the helper in the encoding of `wait4`.
///
/// # Errors
///
/// Gives `ENOENT` before the boot gave a file system, `ENOMEM`, or the error of the `execve`.
pub(crate) fn call(
    path: &[u8],
    argv: Vec<Vec<u8>>,
    envp: Vec<Vec<u8>>,
    setup: impl FnOnce(&Arc<Thread>),
) -> Result<i32, Errno> {
    let fs = FS.lock().clone().ok_or(Errno::ENOENT)?;
    let thread = rk_proc::create_helper(fs)?;
    setup(&thread);
    let process = thread.process().clone();
    let failed: Arc<SpinLock<Option<Errno>>> = Arc::new(SpinLock::new(None));
    let (run_thread, run_failed) = (thread.clone(), failed.clone());
    let args = ExecArgs::new(path.to_vec(), argv, envp);
    let task = TaskOptions::new(move || match exec(&run_thread, args, random16(), |_| {}) {
        Ok(image) => {
            run(run_thread, UserContext::new(VirtAddr::new(image.entry), VirtAddr::new(image.sp)))
        }
        Err(e) => {
            *run_failed.lock() = Some(e);
            rk_proc::exit_thread(&run_thread, WaitStatus::exited(0));
        }
    })
    .data(thread.clone())
    .group(thread.cgroup())
    .spawn();
    let Some(task) = task else {
        rk_proc::exit_thread(&thread, WaitStatus::exited(0));
        return Err(Errno::ENOMEM);
    };
    thread.set_task(&task);
    let status = process.exit_poll().wait_until(|| process.exit_status());
    match *failed.lock() {
        Some(e) => Err(e),
        None => Ok(status.0),
    }
}
