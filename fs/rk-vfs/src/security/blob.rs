//! The security blobs: the memory that each LSM keeps on an object, as the `security` fields of
//! `struct cred`, `struct file`, `struct inode` and the other objects of Linux.
//!
//! Each LSM gives the size of its part of each blob in `LsmInfo::blobs`. At boot the framework
//! gives each module an offset in the blob of each object type, as `lsm_blob_size_update` of
//! Linux. A blob is a block of 64-bit atomic words, so a module can keep its state in it without
//! `unsafe` code. With no module that asks for space, a blob has no memory.

use crate::inode::{Inode, InodeRef};
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use rk_frame::sync::SpinLock;

/// The size in bytes of the part of each object type that an LSM asks for, or, after the boot,
/// the offset of the part in the blob, as `struct lsm_blob_sizes` of Linux.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BlobSizes {
    /// The credentials, `lbs_cred`.
    pub cred: usize,
    /// An open file, `lbs_file`.
    pub file: usize,
    /// An inode, `lbs_inode`.
    pub inode: usize,
    /// A System V IPC object, `lbs_ipc`.
    pub ipc: usize,
    /// A socket, `lbs_sock`.
    pub sock: usize,
    /// A super block, `lbs_superblock`.
    pub superblock: usize,
    /// A task, `lbs_task`.
    pub task: usize,
}

impl BlobSizes {
    /// No space in any blob.
    pub const NONE: Self =
        Self { cred: 0, file: 0, inode: 0, ipc: 0, sock: 0, superblock: 0, task: 0 };

    /// Adds the sizes `req` of one module to the totals `self`, and gives the offsets of the
    /// module, as `lsm_prepare` and `lsm_blob_size_update` of Linux. Each part starts at a
    /// multiple of 8 bytes. A size of 0 gives the offset 0, and the module has no part.
    pub fn add(&mut self, req: &Self) -> Self {
        fn one(total: &mut usize, req: usize) -> usize {
            if req == 0 {
                return 0;
            }
            let offset = total.next_multiple_of(8);
            *total = offset + req;
            offset
        }
        Self {
            cred: one(&mut self.cred, req.cred),
            file: one(&mut self.file, req.file),
            inode: one(&mut self.inode, req.inode),
            ipc: one(&mut self.ipc, req.ipc),
            sock: one(&mut self.sock, req.sock),
            superblock: one(&mut self.superblock, req.superblock),
            task: one(&mut self.task, req.task),
        }
    }
}

/// The security blob of one object. It holds the parts of all the LSMs that asked for space in
/// this object type.
#[derive(Default)]
pub struct Blob(Option<Box<[AtomicU64]>>);

impl Blob {
    /// A blob with no memory.
    pub const EMPTY: Self = Self(None);

    /// A blob of `bytes` bytes, set to zero.
    pub fn new(bytes: usize) -> Self {
        if bytes == 0 {
            return Self::EMPTY;
        }
        Self(Some((0..bytes.div_ceil(8)).map(|_| AtomicU64::new(0)).collect()))
    }

    /// A blob of the size of the credentials blob.
    pub fn cred() -> Self {
        Self::new(super::sizes().cred)
    }

    /// A blob of the size of the file blob.
    pub fn file() -> Self {
        Self::new(super::sizes().file)
    }

    /// A blob of the size of the socket blob.
    pub fn sock() -> Self {
        Self::new(super::sizes().sock)
    }

    /// A blob of the size of the task blob.
    pub fn task() -> Self {
        Self::new(super::sizes().task)
    }

    /// The size of the blob in bytes, a multiple of 8.
    pub fn len(&self) -> usize {
        self.0.as_ref().map_or(0, |w| w.len() * 8)
    }

    /// The blob has no memory.
    pub fn is_empty(&self) -> bool {
        self.0.is_none()
    }

    /// The words of the part at the byte offset `offset` with `len` bytes, or `None` if the
    /// blob is too small. A module gets `offset` from `LsmInfo::offsets`.
    pub fn words(&self, offset: usize, len: usize) -> Option<&[AtomicU64]> {
        let w = self.0.as_deref()?;
        let start = offset / 8;
        w.get(start..start + len.div_ceil(8))
    }

    /// Reads the word at the byte offset `offset`. A blob that is too small gives 0.
    pub fn load(&self, offset: usize) -> u64 {
        self.words(offset, 8).map_or(0, |w| w[0].load(Ordering::Acquire))
    }

    /// Writes the word at the byte offset `offset`. A blob that is too small takes no write.
    pub fn store(&self, offset: usize, value: u64) {
        if let Some(w) = self.words(offset, 8) {
            w[0].store(value, Ordering::Release);
        }
    }

    /// Copies the words of `other` into this blob, as far as both have words.
    pub fn copy_from(&self, other: &Self) {
        if let (Some(a), Some(b)) = (self.0.as_deref(), other.0.as_deref()) {
            for (a, b) in a.iter().zip(b) {
                a.store(b.load(Ordering::Acquire), Ordering::Release);
            }
        }
    }
}

/// A copy has the values of the original, as the copy of the credentials blob in
/// `security_prepare_creds` of Linux before the `cred_prepare` hooks.
impl Clone for Blob {
    fn clone(&self) -> Self {
        let new = Self::new(self.len());
        new.copy_from(self);
        new
    }
}

impl PartialEq for Blob {
    fn eq(&self, other: &Self) -> bool {
        let words = |b: &Self| -> Vec<u64> {
            b.0.as_deref()
                .map_or(Vec::new(), |w| w.iter().map(|x| x.load(Ordering::Acquire)).collect())
        };
        words(self) == words(other)
    }
}

impl Eq for Blob {}

impl core::fmt::Debug for Blob {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Blob({} bytes)", self.len())
    }
}

/// The blobs of the inodes. rukernel has no common inode structure, so the blobs are in a table
/// that the address of the inode keys, as `INODE_WRITERS` of the file module. An entry holds a
/// weak reference to the inode, so a new inode at the address of a dropped one gets a new blob.
struct InodeBlobs {
    map: BTreeMap<usize, (Weak<dyn Inode>, Arc<Blob>)>,
    /// The size of `map` at which the next insert removes the entries of dropped inodes. It is
    /// twice the count of the entries that stayed after the last removal.
    prune_at: usize,
}

static INODES: SpinLock<InodeBlobs> =
    SpinLock::new(InodeBlobs { map: BTreeMap::new(), prune_at: 64 });

fn inode_key(inode: &dyn Inode) -> usize {
    core::ptr::from_ref(inode).cast::<u8>() as usize
}

/// Gives `inode` its blob if a module asks for inode space and the inode has none yet, as
/// `security_inode_alloc` of Linux. The VFS calls it when a dentry gets the inode, as
/// `d_instantiate`. Then the `inode_alloc_security` and `d_instantiate` hooks run.
pub fn inode_attach(inode: &InodeRef) {
    let size = super::sizes().inode;
    if size == 0 {
        return;
    }
    let key = inode_key(&**inode);
    let blob = {
        let mut t = INODES.lock();
        if let Some((weak, _)) = t.map.get(&key)
            && weak.strong_count() > 0
        {
            return;
        }
        if t.map.len() >= t.prune_at {
            t.map.retain(|_, (w, _)| w.strong_count() > 0);
            t.prune_at = (t.map.len() * 2).max(64);
        }
        let blob = Arc::new(Blob::new(size));
        t.map.insert(key, (Arc::downgrade(inode), blob.clone()));
        blob
    };
    super::inode_alloc_security(&**inode, &blob);
    super::d_instantiate(&**inode);
}

/// The blob of `inode`, or `None` if no module asks for inode space or the inode has no blob
/// yet, as `selinux_inode` of Linux.
pub fn inode_blob(inode: &dyn Inode) -> Option<Arc<Blob>> {
    if super::sizes().inode == 0 {
        return None;
    }
    let t = INODES.lock();
    let (weak, blob) = t.map.get(&inode_key(inode))?;
    (weak.strong_count() > 0).then(|| blob.clone())
}

/// The blobs of the super blocks, by the device number of the file system. An entry holds a
/// weak reference to the root of the file system, so the blob goes when the file system goes.
static SUPERS: SpinLock<BTreeMap<u64, (Weak<dyn Inode>, Arc<Blob>)>> =
    SpinLock::new(BTreeMap::new());

/// Gives the file system with the root `root` its blob if a module asks for super block space
/// and the file system has none yet, as `security_sb_alloc` of Linux. Then the
/// `sb_alloc_security` hooks run. The mount code calls it when it makes a file system. The
/// blobs of the file systems that went away go first, and their `sb_free_security` hooks run,
/// as `security_sb_free` of Linux.
pub fn superblock_attach(root: &InodeRef) {
    let size = super::sizes().superblock;
    if size == 0 {
        return;
    }
    let dev = root.metadata().dev;
    let (blob, gone) = {
        let mut t = SUPERS.lock();
        if let Some((weak, _)) = t.get(&dev)
            && weak.strong_count() > 0
        {
            return;
        }
        let dead: Vec<u64> =
            t.iter().filter(|(_, (w, _))| w.strong_count() == 0).map(|(d, _)| *d).collect();
        let gone: Vec<(u64, Arc<Blob>)> =
            dead.into_iter().filter_map(|d| t.remove(&d).map(|(_, b)| (d, b))).collect();
        let blob = Arc::new(Blob::new(size));
        t.insert(dev, (Arc::downgrade(root), blob.clone()));
        (blob, gone)
    };
    for (d, b) in &gone {
        super::sb_free_security(*d, b);
    }
    super::sb_alloc_security(dev, &blob);
}

/// The blob of the file system `dev`, or `None` if no module asks for super block space or the
/// file system has no blob.
pub fn superblock_blob(dev: u64) -> Option<Arc<Blob>> {
    let t = SUPERS.lock();
    let (weak, blob) = t.get(&dev)?;
    (weak.strong_count() > 0).then(|| blob.clone())
}

/// The class of a System V IPC object.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum IpcClass {
    /// A message queue.
    Msg,
    /// A semaphore set.
    Sem,
    /// A shared memory segment.
    Shm,
}

/// The security part of a System V IPC object: its class and its blob, as the `security` field
/// of `struct kern_ipc_perm` of Linux. The object keeps it in its table entry. When it is
/// dropped, the `*_free_security` hooks of its class run.
#[derive(Debug, PartialEq, Eq)]
pub struct IpcSecurity {
    class: IpcClass,
    blob: Blob,
}

impl IpcSecurity {
    /// The part of a new object of the class `class`, with a blob of the size of the IPC blob.
    /// The caller then calls [`super::ipc_alloc`].
    pub fn new(class: IpcClass) -> Self {
        Self { class, blob: Blob::new(super::sizes().ipc) }
    }

    /// The class of the object.
    pub fn class(&self) -> IpcClass {
        self.class
    }

    /// The blob of the object.
    pub fn blob(&self) -> &Blob {
        &self.blob
    }
}

/// As Linux, the free hooks also run for an object whose alloc hooks failed.
impl Drop for IpcSecurity {
    fn drop(&mut self) {
        super::ipc_free(self);
    }
}
