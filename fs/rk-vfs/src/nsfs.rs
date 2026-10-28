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
use rk_abi::native::sched;
use rk_frame::sync::Once;

/// The magic number of nsfs, `NSFS_MAGIC` of `<linux/magic.h>`.
pub const NSFS_MAGIC: u64 = 0x6e73_6673;

/// The kinds of namespace that have a file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NsKind {
    /// A cgroup namespace.
    Cgroup,
    /// An IPC namespace. rukernel has only the first one.
    Ipc,
    /// A mount namespace.
    Mnt,
    /// A PID namespace. rukernel has only the first one.
    Pid,
    /// A time namespace. rukernel has only the first one.
    Time,
    /// A user namespace. rukernel has only the first one.
    User,
    /// A UTS namespace. rukernel has only the first one.
    Uts,
}

impl NsKind {
    /// The name of the kind: the name of the link in `/proc/PID/ns`.
    pub fn name(self) -> &'static str {
        match self {
            Self::Cgroup => "cgroup",
            Self::Ipc => "ipc",
            Self::Mnt => "mnt",
            Self::Pid => "pid",
            Self::Time => "time",
            Self::User => "user",
            Self::Uts => "uts",
        }
    }

    /// The `CLONE_NEW*` flag of the kind, for the `nstype` of `setns`.
    pub fn clone_flag(self) -> u64 {
        match self {
            Self::Cgroup => sched::CLONE_NEWCGROUP,
            Self::Ipc => sched::CLONE_NEWIPC,
            Self::Mnt => sched::CLONE_NEWNS,
            Self::Pid => sched::CLONE_NEWPID,
            Self::Time => sched::CLONE_NEWTIME,
            Self::User => sched::CLONE_NEWUSER,
            Self::Uts => sched::CLONE_NEWUTS,
        }
    }

    /// The inode number of the first namespace of the kind, `PROC_*_INIT_INO` of Linux.
    fn init_ino(self) -> u64 {
        match self {
            Self::Ipc => 0xEFFF_FFFF,
            Self::Uts => 0xEFFF_FFFE,
            Self::User => 0xEFFF_FFFD,
            Self::Pid => 0xEFFF_FFFC,
            Self::Cgroup => 0xEFFF_FFFB,
            Self::Time => 0xEFFF_FFFA,
            Self::Mnt => 0xEFFF_FFF8,
        }
    }

    /// The first inode number of the other namespaces of the kind.
    fn base(self) -> u64 {
        match self {
            Self::Cgroup => 0xF000_0000,
            Self::Mnt => 0xF100_0000,
            // The other kinds have only the first namespace.
            _ => 0xF200_0000,
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
