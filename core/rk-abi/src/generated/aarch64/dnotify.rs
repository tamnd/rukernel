// rk-abigen generated this file from Linux 7.3, from <linux/fcntl.h>.
// Do not edit it. Change rk-abigen and run it again.

//! The events of `F_NOTIFY`.

/// File accessed.
pub const DN_ACCESS: u32 = 1;
/// File modified.
pub const DN_MODIFY: u32 = 2;
/// File created.
pub const DN_CREATE: u32 = 4;
/// File removed.
pub const DN_DELETE: u32 = 8;
/// File renamed.
pub const DN_RENAME: u32 = 16;
/// File changed attibutes.
pub const DN_ATTRIB: u32 = 32;
/// Don't remove notifier.
pub const DN_MULTISHOT: u32 = 0x8000_0000;
