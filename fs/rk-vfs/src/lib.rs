//! The virtual file system of rukernel.
//!
//! The VFS gives one model of files to each file system, per spec/08-vfs-and-filesystems.md. A
//! file system gives `Inode` objects. The VFS keeps the dentries of the names in use, the mounts
//! of a name space and the open files, walks paths, and does the part of each system call on
//! names that is the same for each file system. It also reads the cpio archive of the initramfs.
//!
//! The crate has no code for one CPU or one architecture, so the tests on the host examine it with
//! tmpfs.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod cpio;
pub mod dentry;
pub mod device;
pub mod fdtable;
pub mod file;
pub mod fs;
pub mod inode;
pub mod path;

pub use dentry::{Dentry, Location, Mount, MountNamespace};
pub use fdtable::{FdEntry, FdTable};
pub use file::{File, FileOps, OpenFlags, UserMemory, Whence};
pub use fs::FsContext;
pub use inode::{
    DirEntry, FileType, Inode, InodeRef, Metadata, Result, SetAttr, Timespec, anon_dev, now,
    set_clock,
};
