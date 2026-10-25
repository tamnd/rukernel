//! The virtual file system of rukernel.
//!
//! The VFS gives one model of files to each file system, per spec/08-vfs-and-filesystems.md. A
//! file system gives `Inode` objects. The VFS keeps the dentries of the names in use, the mounts
//! of a name space and the open files, walks paths, and does the part of each system call on
//! names that is the same for each file system. It also keeps the list of file system types and
//! reads the cpio archive of the initramfs.
//!
//! The crate has no code for one CPU or one architecture, so the tests on the host examine it with
//! tmpfs.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod acl;
pub mod blockdev;
pub mod cpio;
pub mod cred;
pub mod dentry;
pub mod device;
pub mod fdtable;
pub mod file;
pub mod fs;
pub mod fstype;
pub mod inode;
pub mod lock;
pub mod mapped;
pub mod path;
pub mod pipe;
pub mod wait;
pub mod xattr;

pub use dentry::{Dentry, Location, Mount, MountNamespace, MountSource};
pub use fdtable::{FdEntry, FdTable};
pub use file::{File, FileOps, OpenFlags, UserMemory, Whence};
pub use fs::FsContext;
pub use inode::{
    DirEntry, FileType, Inode, InodeRef, Metadata, Result, SetAttr, Timespec, anon_dev, now,
    set_clock,
};
pub use wait::WaitQueue;
