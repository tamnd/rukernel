//! The pages of the files that a process mapped, as the VFS sees them.
//!
//! A file mapping keeps a copy of each page of the file that it uses. The VFS keeps these copies
//! the same as the file, as the page cache of Linux does for `read`, `write` and a mapping. A
//! write copies its data to the pages, a truncate and a `fallocate` read the changed pages again,
//! and a read first writes back the pages that the mapping changed.

use crate::inode::InodeRef;
use crate::inode::Result;
use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use rk_frame::sync::SpinLock;

/// The copies of the pages of one mapped file.
pub trait Mapped: Send + Sync {
    /// Copies `data`, which a write put at `offset` of the file, to the pages.
    fn wrote(&self, offset: u64, data: &[u8]);

    /// Reads again the pages that have a byte from `start` to `end` of the file.
    fn changed(&self, start: u64, end: u64);

    /// Writes back the changed pages that have a byte from `start` to `end` of the file.
    ///
    /// # Errors
    ///
    /// Gives the error of the write.
    fn sync(&self, start: u64, end: u64) -> Result<()>;
}

/// The mapped files, by the address of the inode.
static MAPPED: SpinLock<BTreeMap<usize, Weak<dyn Mapped>>> = SpinLock::new(BTreeMap::new());

fn key(inode: &InodeRef) -> usize {
    Arc::as_ptr(inode).cast::<()>() as usize
}

/// Records `pages` as the copies of the pages of `inode`. The record goes when `pages` goes.
pub fn register(inode: &InodeRef, pages: Weak<dyn Mapped>) {
    let mut map = MAPPED.lock();
    map.retain(|_, p| p.strong_count() > 0);
    map.insert(key(inode), pages);
}

/// The copies of the pages of `inode`, if a process mapped it.
fn find(inode: &InodeRef) -> Option<Arc<dyn Mapped>> {
    let map = MAPPED.lock();
    if map.is_empty() {
        return None;
    }
    map.get(&key(inode)).and_then(Weak::upgrade)
}

/// Copies `data`, which a write put at `offset` of `inode`, to its mapped pages.
pub fn wrote(inode: &InodeRef, offset: u64, data: &[u8]) {
    if let Some(pages) = find(inode) {
        pages.wrote(offset, data);
    }
}

/// Reads again the mapped pages of `inode` from `start` up to `end`.
pub fn changed(inode: &InodeRef, start: u64, end: u64) {
    if let Some(pages) = find(inode) {
        pages.changed(start, end);
    }
}

/// Writes back the changed mapped pages of `inode` from `start` up to `end`, before a read.
///
/// # Errors
///
/// Gives the error of the write.
pub fn sync(inode: &InodeRef, start: u64, end: u64) -> Result<()> {
    match find(inode) {
        Some(pages) => pages.sync(start, end),
        None => Ok(()),
    }
}
