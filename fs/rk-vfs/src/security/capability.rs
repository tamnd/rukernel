//! The capability module, as security/commoncap.c of Linux. It is always the first module.
//!
//! The module checks the effective set of the credentials in the `capable` hook, as
//! `cap_capable`. The other checks of commoncap.c are in [`crate::cred::Cred`]: the change of the
//! capabilities at `execve` and at a change of the user IDs, and `capset`.

use super::hooks::SecurityHooks;
use super::{BlobSizes, LsmId, LsmInfo, Order, id};
use crate::cred::{Cred, cap};
use crate::inode::Result;
use rk_abi::Errno;

/// The hooks of the capability module.
pub struct Capability;

impl SecurityHooks for Capability {
    fn capable(&self, cred: &Cred, c: u32, _opts: u32) -> Result<()> {
        if cred.cap_effective & cap::bit(c) != 0 { Ok(()) } else { Err(Errno::EPERM) }
    }
}

/// The capability module, `capability` in /sys/kernel/security/lsm.
pub static LSM: LsmInfo = LsmInfo {
    id: LsmId { name: "capability", id: id::CAPABILITY },
    order: Order::First,
    flags: 0,
    blobs: BlobSizes::NONE,
    hooks: &Capability,
};
