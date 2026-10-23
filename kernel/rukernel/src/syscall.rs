//! The system call table.
//!
//! Each system call number goes to a handler. In R0 no system call has a handler yet, so each
//! number gives `ENOSYS`, as Linux gives for a number that it does not know. R1 adds the first
//! handlers, per spec/22-milestones.md.

use core::sync::atomic::{AtomicU64, Ordering};
use rk_abi::Errno;
use rk_frame::user::UserContext;

/// The number of system calls since boot.
static COUNT: AtomicU64 = AtomicU64::new(0);

/// Gives the number of system calls since boot.
pub(crate) fn count() -> u64 {
    COUNT.load(Ordering::Relaxed)
}

/// Handles the system call in `ctx` and puts the return value in it.
pub(crate) fn dispatch(ctx: &mut UserContext) {
    COUNT.fetch_add(1, Ordering::Relaxed);
    let ret = handle(ctx.syscall_number(), ctx.syscall_args());
    let value = match ret {
        Ok(v) => v,
        Err(e) => e.to_syscall_return() as u64,
    };
    ctx.set_syscall_return(value);
}

/// Runs the handler of the system call `nr`. A number outside the table gives `ENOSYS` too.
fn handle(_nr: u64, _args: [u64; 6]) -> Result<u64, Errno> {
    Err(Errno::ENOSYS)
}
