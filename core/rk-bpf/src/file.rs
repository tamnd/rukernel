//! The files of the BPF objects, `bpf_map_fops` in kernel/bpf/syscall.c of Linux.
//!
//! A map file is an anonymous inode file with the name `bpf-map`. A read or a write of the file
//! gives `EINVAL`, as `bpf_dummy_read` and `bpf_dummy_write` of Linux. `/proc/PID/fdinfo` shows
//! the attributes of the map, as `bpf_map_show_fdinfo` of Linux. A process can map the values
//! of an array map with `BPF_F_MMAPABLE`, as `bpf_map_mmap` of Linux.

use crate::map::BpfMap;
use crate::uapi::flags::BPF_F_RDONLY_PROG;
use crate::value::Page;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;
use rk_abi::Errno;
use rk_frame::sync::Once;
use rk_vfs::file::{File, FileOps};
use rk_vfs::inode::Metadata;

/// The operations of a map file.
pub struct BpfMapFile {
    /// The map.
    pub map: Arc<BpfMap>,
}

impl BpfMapFile {
    /// Makes the file of a new descriptor of `map`. The descriptor counts in `usercnt`, as
    /// `bpf_map_inc_with_uref` of Linux.
    pub fn new(map: Arc<BpfMap>) -> Self {
        map.inc_uref();
        Self { map }
    }
}

impl Drop for BpfMapFile {
    /// The last close of the file, `bpf_map_release` of Linux.
    fn drop(&mut self) {
        self.map.put_uref();
    }
}

/// The device of the anonymous inode, which all files of anon_inode_getfd of Linux share.
fn anon_inode_dev() -> u64 {
    static DEV: Once<u64> = Once::new();
    *DEV.call_once(rk_vfs::inode::anon_dev)
}

/// The attributes of the anonymous inode. It has the mode 0600 and no file type, as in Linux.
pub(crate) fn anon_inode_metadata() -> Metadata {
    Metadata {
        dev: anon_inode_dev(),
        ino: 1,
        mode: 0o600,
        nlink: 1,
        blksize: 4096,
        ..Metadata::default()
    }
}

impl FileOps for BpfMapFile {
    fn metadata(&self) -> Option<Metadata> {
        Some(anon_inode_metadata())
    }

    fn as_any(&self) -> Option<&dyn core::any::Any> {
        Some(self)
    }

    fn fdinfo(&self, _file: &File) -> Vec<u8> {
        self.map.show_fdinfo()
    }
}

/// The map of a file, `__bpf_map_get` of Linux. A file that is not a map gives `None`.
pub fn bpf_map_of(file: &File) -> Option<Arc<BpfMap>> {
    file.ops().as_any()?.downcast_ref::<BpfMapFile>().map(|f| f.map.clone())
}

/// A mapping of the values of a map, which `bpf_map_mmap` of Linux makes.
pub struct MapMmap {
    /// The pages of the values, from the start of the map.
    pub pages: Arc<[Arc<Page>]>,
    /// The mapping can get write access later, `VM_MAYWRITE` of Linux.
    pub may_write: bool,
    /// The map, if the mapping counts in `writecnt`.
    writer: Option<Arc<BpfMap>>,
}

impl Drop for MapMmap {
    /// The last area of the mapping is gone, `bpf_map_mmap_close` of Linux.
    fn drop(&mut self) {
        if let Some(map) = &self.writer {
            map.writecnt.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

/// Maps `len` bytes of the values of `map` at the page `pgoff`, `bpf_map_mmap` of Linux. Only a
/// shared mapping is possible. A mapping that writes counts as a writer of the map until it is
/// gone, so `BPF_MAP_FREEZE` gives `EBUSY` while it exists. A mapping that only reads cannot get
/// write access later.
///
/// # Errors
///
/// `ENOTSUPP` for a map that a process cannot map, `EINVAL` for a private mapping or for bytes
/// past the values, `EPERM` for a write mapping of a frozen map, and `EACCES` for a write mapping
/// of a map with `BPF_F_RDONLY_PROG`.
pub fn bpf_map_mmap(
    map: &Arc<BpfMap>,
    shared: bool,
    write: bool,
    pgoff: u64,
    len: u64,
) -> Result<MapMmap, Errno> {
    // Test the type first, as `map_mmap` is not set for a map that is not an array.
    let pages = map.ops.map_mmap(pgoff, len);
    if pages.as_ref().err() == Some(&Errno::ENOTSUPP) {
        return Err(Errno::ENOTSUPP);
    }
    if !shared {
        return Err(Errno::EINVAL);
    }
    let _guard = map.freeze_mutex.lock();
    if write {
        if map.frozen.load(Ordering::Acquire) {
            return Err(Errno::EPERM);
        }
        // The program reads the map as constant, so no process can write it.
        if map.map_flags & BPF_F_RDONLY_PROG != 0 {
            return Err(Errno::EACCES);
        }
    }
    let pages = pages?;
    let writer = write.then(|| {
        map.writecnt.fetch_add(1, Ordering::AcqRel);
        map.clone()
    });
    Ok(MapMmap { pages, may_write: write, writer })
}
