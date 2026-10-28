//! nsfs: the files of the namespaces. A link of `/proc/PID/ns` goes to such a file, and `setns`
//! takes a descriptor of it, as `fs/nsfs.c` of Linux.
//!
//! The file only names a namespace: a kind and the ID that the owner of the namespace gives. The
//! inode number is the number that `readlink` of the link shows, as `ns_common.inum` of Linux.

use crate::inode::{Inode, InodeRef, Metadata, Result, SetAttr, mode};
use alloc::format;
use alloc::sync::Arc;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_frame::sync::Once;

/// The magic number of nsfs, `NSFS_MAGIC` of `<linux/magic.h>`.
pub const NSFS_MAGIC: u64 = 0x6e73_6673;

/// The kinds of namespace that have a file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NsKind {
    /// A cgroup namespace.
    Cgroup,
}

impl NsKind {
    /// The name of the kind: the name of the link in `/proc/PID/ns`.
    pub fn name(self) -> &'static str {
        match self {
            Self::Cgroup => "cgroup",
        }
    }

    /// The `CLONE_NEW*` flag of the kind, for the `nstype` of `setns`.
    pub fn clone_flag(self) -> u64 {
        match self {
            Self::Cgroup => rk_abi::native::sched::CLONE_NEWCGROUP,
        }
    }

    /// The inode number of the first namespace of the kind, `PROC_*_INIT_INO` of Linux.
    fn init_ino(self) -> u64 {
        match self {
            Self::Cgroup => 0xEFFF_FFFB,
        }
    }

    /// The first inode number of the other namespaces of the kind.
    fn base(self) -> u64 {
        match self {
            Self::Cgroup => 0xF000_0000,
        }
    }
}

/// The inode of a namespace.
pub struct NsInode {
    kind: NsKind,
    id: u32,
}

impl NsInode {
    /// Makes the inode of the namespace `id` of the kind `kind`. The ID 0 is the first namespace
    /// of the kind.
    pub fn new(kind: NsKind, id: u32) -> Arc<Self> {
        Arc::new(Self { kind, id })
    }

    /// The inode number of the namespace.
    pub fn ino(kind: NsKind, id: u32) -> u64 {
        if id == 0 { kind.init_ino() } else { kind.base() + u64::from(id) }
    }
}

/// The text of the link to the namespace `id` of the kind `kind`, as `cgroup:[4026531835]`.
pub fn link_text(kind: NsKind, id: u32) -> Vec<u8> {
    format!("{}:[{}]", kind.name(), NsInode::ino(kind, id)).into_bytes()
}

/// The kind and the ID of the namespace of `inode`, or `None` if it is not the inode of a
/// namespace.
pub fn ns_of(inode: &InodeRef) -> Option<(NsKind, u32)> {
    let any: &dyn core::any::Any = &**inode;
    any.downcast_ref::<NsInode>().map(|n| (n.kind, n.id))
}

/// The device of nsfs.
fn dev() -> u64 {
    static DEV: Once<u64> = Once::new();
    *DEV.call_once(crate::inode::anon_dev)
}

impl Inode for NsInode {
    fn metadata(&self) -> Metadata {
        Metadata {
            dev: dev(),
            ino: Self::ino(self.kind, self.id),
            mode: mode::S_IFREG | 0o444,
            nlink: 1,
            ..Metadata::default()
        }
    }

    fn set_attr(&self, _attr: &SetAttr) -> Result<()> {
        Err(Errno::EPERM)
    }

    fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> Result<usize> {
        Err(Errno::EINVAL)
    }

    fn fs_magic(&self) -> u64 {
        NSFS_MAGIC
    }
}
