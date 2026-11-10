//! The files of the BPF objects, `bpf_map_fops` in kernel/bpf/syscall.c of Linux.
//!
//! A map file is an anonymous inode file with the name `bpf-map`. A read or a write of the file
//! gives `EINVAL`, as `bpf_dummy_read` and `bpf_dummy_write` of Linux. `/proc/PID/fdinfo` shows
//! the attributes of the map, as `bpf_map_show_fdinfo` of Linux.

use crate::map::BpfMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
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
