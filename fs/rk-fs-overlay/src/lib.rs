//! overlayfs: a file system that joins directories of other file systems.
//!
//! A mount has one or more lower directories, which it does not change, and an upper directory,
//! which takes all the changes. A name in the upper directory hides the same name in the lower
//! directories, and the entries of two directories with the same name are joined. The first
//! change of a file of a lower directory copies the file to the upper directory. A removal of a
//! name that a lower directory has makes a whiteout, a character device 0:0, in the upper
//! directory. A directory with the extended attribute `trusted.overlay.opaque` set to `y` hides
//! the lower directories. Linux has the same design in fs/overlayfs.
//!
//! A mount without an upper directory does not accept changes. A rename of a directory that is
//! in a lower directory gives `EXDEV`, as Linux without the `redirect_dir` feature, and `mv`
//! then copies the directory. With `redirect_dir=on`, the rename sets the attribute
//! `trusted.overlay.redirect` of the upper directory to the old name or to the old path, and a
//! lookup follows it to the lower directories.
//!
//! With `metacopy=on`, a change of the attributes of a regular file copies up only the
//! attributes. The upper file gets the attribute `trusted.overlay.metacopy`, and the data stays
//! in the lower layer until a change of the data. A metacopy file can find its data in a
//! data-only layer through an absolute redirect.
//!
//! With `index=on`, a copy up of a lower hard link puts the upper file in the directory `index`
//! of the work directory, with the file handle of the lower inode as its name. The upper
//! directory gets a link to it. The other lower hard links of the same lower inode then show
//! the same upper file, and the attribute `trusted.overlay.nlink` of the upper file keeps the
//! count of the links of the overlay file.
//!
//! The extended attributes of overlayfs have the prefix `trusted.overlay.`, or `user.overlay.`
//! with the option `userxattr`. A user cannot see them through the mount. A user attribute with
//! the prefix gets `overlay.` after the prefix in the layer, as the escapes of Linux, so an
//! overlay can be a lower layer of another overlay.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

mod params;

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::format;
use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use params::{Options, Redirect, Uuid};
use rk_abi::Errno;
use rk_frame::sync::SpinLock;
use rk_vfs::fstype::{FsType, MountArgs};
use rk_vfs::inode::{FsStat, check_immutable, iflags, mode};
use rk_vfs::{DirEntry, FileType, Inode, InodeRef, Metadata, Result, SetAttr, Timespec, acl};

/// The magic number of overlayfs, `OVERLAYFS_SUPER_MAGIC` of `<linux/magic.h>`.
pub const OVERLAYFS_SUPER_MAGIC: u64 = 0x794c_7630;

/// The file system type for `mount -t overlay`.
pub const FS_TYPE: FsType = FsType { name: "overlay", nodev: true, make: mount };

/// The prefix of the extended attributes of overlayfs.
const TRUSTED: &[u8] = b"trusted.overlay.";
/// The prefix of the extended attributes of overlayfs with the option `userxattr`.
const USER: &[u8] = b"user.overlay.";
/// The part after the prefix of an attribute of a user that has the prefix of overlayfs.
const ESCAPE: &[u8] = b"overlay.";
/// The attribute that makes a directory opaque with the value `y`. The value `x` tells that the
/// directory can have whiteouts that are regular files with [`WHITEOUT`].
const OPAQUE: &[u8] = b"opaque";
/// The attribute that makes a regular file of size 0 a whiteout.
const WHITEOUT: &[u8] = b"whiteout";
/// The attribute that keeps the immutable and append-only flags of an upper file, as the
/// letters `i` and `a`. The upper inode does not get these flags, so the mount can still change
/// it.
const PROTATTR: &[u8] = b"protattr";
/// The attribute of a moved upper inode that tells where the lower inodes are: the old name in
/// the same directory, or an absolute path from the roots of the layers.
const REDIRECT: &[u8] = b"redirect";
/// The attribute of a regular file of a layer that has the attributes but not the data.
const METACOPY: &[u8] = b"metacopy";
/// The attribute of an upper inode with the file handle of the lower inode that a copy up
/// copied.
const ORIGIN: &[u8] = b"origin";
/// The attribute of an upper directory that can have names with the inode numbers of lower
/// inodes.
const IMPURE: &[u8] = b"impure";
/// The attribute of the upper root with the uuid of the overlay.
const UUID: &[u8] = b"uuid";
/// The attribute of an upper file in the index with the count of the links of the overlay file,
/// as a difference to the count of the links of the upper inode or of the lower inode: `U` or
/// `L`, then a sign and a number, as `U-1`.
const NLINK: &[u8] = b"nlink";
/// The attribute of the index directory with the file handle of the upper root.
const UPPER: &[u8] = b"upper";
/// The inode flags that the attribute [`PROTATTR`] keeps.
const PROT_FLAGS: u32 = iflags::IMMUTABLE | iflags::APPEND;
/// The inode flags that a copy up gives to the upper inode.
const COPY_FLAGS: u32 = iflags::SYNC | iflags::NOATIME;
/// The name of the directory that overlayfs makes in the work directory.
const WORK: &[u8] = b"work";
/// The name of the index directory in the work directory, for the option `index`.
const INDEX: &[u8] = b"index";
/// The bytes that a copy up moves in one step.
const CHUNK: usize = 64 * 1024;
/// The maximum count of the unused nodes that one mount keeps, as the dentries on the LRU list
/// of Linux.
const UNUSED_MAX: usize = 4096;
/// The magic number of the attribute [`ORIGIN`], `OVL_FH_MAGIC` of Linux.
const FH_MAGIC: u8 = 0xfb;
/// The size of the header of the attribute [`ORIGIN`], as `struct ovl_fb` of Linux: the version,
/// the magic number, the size, the flags, the type of the file handle and a uuid of 16 bytes. The
/// words of the file handle come after it.
const FH_HEADER: usize = 21;

/// The upper and work directories that a mount uses, as a file system id and an inode number, as
/// the `I_OVL_INUSE` flag of Linux.
static IN_USE: SpinLock<BTreeSet<(u64, u64)>> = SpinLock::new(BTreeSet::new());

/// The directories of [`IN_USE`] that one mount holds. The drop releases them.
#[derive(Default)]
struct InUse(Vec<(u64, u64)>);

impl InUse {
    /// Marks the directory `dir` as in use by this mount, as `ovl_inuse_trylock` of Linux.
    /// Tells if no other mount uses it.
    fn take(&mut self, dir: &InodeRef) -> bool {
        let key = (dir.fs_id(), dir.metadata().ino);
        let free = IN_USE.lock().insert(key);
        if free {
            self.0.push(key);
        }
        free
    }
}

impl Drop for InUse {
    fn drop(&mut self) {
        let mut set = IN_USE.lock();
        for key in &self.0 {
            set.remove(key);
        }
    }
}

/// One mount of overlayfs.
struct Fs {
    /// The device of the mount, for the directories.
    dev: u64,
    /// Tells if the mount accepts changes. A mount without an upper directory does not, and a
    /// mount that cannot make its work directory does not, as Linux.
    writable: bool,
    /// The upper layer has POSIX ACLs, so a user can set an ACL through the mount.
    upper_acl: bool,
    /// Tells if the mount is read only now: it does not accept changes, or a remount made it
    /// read only.
    read_only: AtomicBool,
    /// The prefix of the extended attributes of overlayfs: [`TRUSTED`] or [`USER`].
    prefix: &'static [u8],
    /// The options of the mount for `/proc/PID/mountinfo`.
    options: Vec<u8>,
    /// The order of the unused nodes, for the eviction.
    cache: Cache,
    /// The roots of the lower layers with their positions, the top layer first. The lookup of
    /// an absolute redirect starts here.
    roots: Vec<(usize, InodeRef)>,
    /// The roots of the data-only lower layers, the top layer first.
    data: Vec<InodeRef>,
    /// The option `redirect_dir`.
    redirect: Redirect,
    /// The option `metacopy`.
    metacopy: bool,
    /// The id of the file system for `statfs`.
    fsid: u64,
    /// For each lower inode, as a device and an inode number, the upper inode that shows the
    /// numbers of the lower inode. Another upper inode of the same lower inode shows its own
    /// numbers, so two files do not have the same numbers.
    inos: SpinLock<BTreeMap<(u64, u64), (u64, u64)>>,
    /// The index directory, with the option `index`. A copy up of a lower hard link puts the
    /// upper file here, with the file handle of the lower inode as the name in hexadecimal. The
    /// other names of the lower inode then find the upper file, so the hard link stays one file.
    index: Option<InodeRef>,
    /// The count of the files that the mount put in the index directory. A node without an upper
    /// inode looks in the index directory again when the count changes.
    indexed: AtomicU64,
    /// The directory for the temporary files: the index directory with the option `index`, or
    /// else the directory `work` in the work directory.
    work: Option<InodeRef>,
    /// The whiteout in [`Fs::work`] with its name, which the new whiteouts link to, as
    /// `ofs->whiteout` of Linux.
    whiteout: SpinLock<Option<(Vec<u8>, InodeRef)>>,
    /// The upper file system cannot link whiteouts, so each whiteout is a new inode.
    no_shared_whiteout: AtomicBool,
    /// The number of the next temporary name.
    temp: AtomicU64,
    /// The upper and work directories that this mount marks as in use.
    _in_use: InUse,
}

impl Fs {
    /// Gives the extended attribute `name` of overlayfs, with the prefix of the mount.
    fn xattr(&self, name: &[u8]) -> Vec<u8> {
        [self.prefix, name].concat()
    }

    /// Tells if `name` is an attribute of overlayfs, which a user cannot see through the mount,
    /// as `ovl_is_private_xattr` of Linux.
    fn is_private(&self, name: &[u8]) -> bool {
        name.strip_prefix(self.prefix).is_some_and(|rest| !rest.starts_with(ESCAPE))
    }

    /// Gives the name in the layer of the attribute `name` of a user: the name with `overlay.`
    /// after the prefix of overlayfs, or the same name.
    fn escape(&self, name: &[u8]) -> Vec<u8> {
        match name.strip_prefix(self.prefix) {
            Some(rest) => [self.prefix, ESCAPE, rest].concat(),
            None => name.to_vec(),
        }
    }

    /// Gives the name that a user sees for the attribute `name` of a layer, or `None` for an
    /// attribute of overlayfs.
    fn unescape(&self, name: &[u8]) -> Option<Vec<u8>> {
        let Some(rest) = name.strip_prefix(self.prefix) else { return Some(name.to_vec()) };
        let rest = rest.strip_prefix(ESCAPE)?;
        Some([self.prefix, rest].concat())
    }

    /// Tells if the directory `inode` hides the lower directories.
    fn is_opaque(&self, inode: &InodeRef) -> bool {
        inode.get_xattr(&self.xattr(OPAQUE)).is_ok_and(|v| v == b"y")
    }

    /// Tells if the directory `dir` can have whiteouts that are regular files.
    fn has_xwhiteouts(&self, dir: &InodeRef) -> bool {
        dir.get_xattr(&self.xattr(OPAQUE)).is_ok_and(|v| v == b"x")
    }

    /// Tells if `inode` in the directory `dir` is a whiteout: a character device 0:0, or a
    /// regular file of size 0 with the attribute [`WHITEOUT`] in a directory that can have such
    /// whiteouts, as `ovl_path_is_whiteout` of Linux.
    fn is_whiteout_in(&self, dir: &InodeRef, inode: &InodeRef) -> bool {
        if is_whiteout(inode) {
            return true;
        }
        let m = inode.metadata();
        m.file_type() == Some(FileType::Regular)
            && m.size == 0
            && inode.get_xattr(&self.xattr(WHITEOUT)).is_ok()
            && self.has_xwhiteouts(dir)
    }

    /// Tells if the entry `entry` of the directory `dir` is a whiteout.
    fn entry_is_whiteout(&self, dir: &InodeRef, entry: &DirEntry) -> bool {
        let maybe = match entry.kind {
            FileType::CharDevice => true,
            FileType::Regular => self.has_xwhiteouts(dir),
            _ => false,
        };
        maybe && dir.lookup(&entry.name).is_ok_and(|i| self.is_whiteout_in(dir, &i))
    }

    /// Gives the flags of [`PROT_FLAGS`] that the upper inode `upper` keeps in [`PROTATTR`].
    fn prot_flags(&self, upper: &InodeRef) -> u32 {
        let value = upper.get_xattr(&self.xattr(PROTATTR)).unwrap_or_default();
        value.iter().fold(0, |flags, &b| match b {
            b'a' => flags | iflags::APPEND,
            b'i' => flags | iflags::IMMUTABLE,
            _ => flags,
        })
    }

    /// Keeps the flags of [`PROT_FLAGS`] in `flags` in the attribute [`PROTATTR`] of the upper
    /// inode `upper`, as `ovl_set_protattr` of Linux. No flag removes the attribute.
    fn set_prot_flags(&self, upper: &InodeRef, flags: u32) -> Result<()> {
        let mut value = Vec::new();
        if flags & iflags::APPEND != 0 {
            value.push(b'a');
        }
        if flags & iflags::IMMUTABLE != 0 {
            value.push(b'i');
        }
        let name = self.xattr(PROTATTR);
        if !value.is_empty() {
            return upper.set_xattr(&name, &value, 0);
        }
        match upper.remove_xattr(&name) {
            Ok(()) | Err(Errno::ENODATA) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Tells if a lookup follows redirects, as `ovl_redirect_follow` of Linux.
    fn follow(&self) -> bool {
        self.redirect != Redirect::NoFollow
    }

    /// Tells if the mount uses a feature that does not accept changes of the lower layers while
    /// the overlay is not mounted, as `!ovl_allow_offline_changes` of Linux.
    fn strict(&self) -> bool {
        self.metacopy || self.redirect == Redirect::On
    }

    /// Tells if the file `inode` of a layer has the attribute [`METACOPY`].
    fn is_metacopy(&self, inode: &InodeRef) -> bool {
        inode.get_xattr(&self.xattr(METACOPY)).is_ok()
    }

    /// Gives the attribute [`REDIRECT`] of `inode`, as `ovl_get_redirect_xattr` of Linux. An
    /// absolute redirect must not have an empty name. A relative redirect must be one name.
    fn redirect_of(&self, inode: &InodeRef) -> Result<Option<Vec<u8>>> {
        let value = match inode.get_xattr(&self.xattr(REDIRECT)) {
            Ok(value) => value,
            Err(Errno::ENODATA | Errno::EOPNOTSUPP) => return Ok(None),
            Err(e) => return Err(e),
        };
        let valid = match value.strip_prefix(b"/") {
            Some(path) => path.split(|&b| b == b'/').all(|name| !name.is_empty()),
            None => !value.is_empty() && !value.contains(&b'/'),
        };
        if valid { Ok(Some(value)) } else { Err(Errno::EINVAL) }
    }

    /// Sets the attribute [`ORIGIN`] of `upper` to the file handle of the lower inode `lower`,
    /// as `ovl_set_origin_fh` of Linux. Tells if it set the attribute. A lower file system
    /// without file handles gives no attribute.
    fn set_origin(&self, upper: &InodeRef, lower: &InodeRef) -> Result<bool> {
        let Some(fh) = encode_fh(lower) else { return Ok(false) };
        match upper.set_xattr(&self.xattr(ORIGIN), &fh, 0) {
            Ok(()) => Ok(true),
            Err(Errno::EOPNOTSUPP) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Gives the lower inode of the file handle `fh` in the format of [`ORIGIN`], as
    /// `ovl_decode_real_fh` of Linux. A handle that is not valid and a handle of a removed inode
    /// give `None`.
    fn decode_fh(&self, fh: &[u8]) -> Option<InodeRef> {
        if !fh_is_valid(fh) {
            return None;
        }
        let id = u64::from_le_bytes(fh[5..13].try_into().ok()?);
        let words: Vec<u32> =
            fh[FH_HEADER..].as_chunks::<4>().0.iter().map(|w| u32::from_le_bytes(*w)).collect();
        let (_, root) = self.roots.iter().find(|(_, root)| root.fs_id() == id)?;
        root.inode_by_handle(i32::from(fh[4]), &words).ok()
    }

    /// Gives the lower inode of the attribute [`ORIGIN`] of `upper`, as `ovl_check_origin` of
    /// Linux. An attribute that is not valid, a handle of a removed inode and an inode of
    /// another type give `None`.
    fn origin(&self, upper: &InodeRef) -> Option<InodeRef> {
        let fh = upper.get_xattr(&self.xattr(ORIGIN)).ok()?;
        let inode = self.decode_fh(&fh)?;
        let same = inode.metadata().file_type() == upper.metadata().file_type();
        same.then_some(inode)
    }

    /// Gives the entry of the lower inode `lower` in the index directory, as `ovl_lookup_index`
    /// of Linux. The entry must be a file of the same type as `lower`, else the lookup gives
    /// `EIO`. If the node has the upper inode `upper`, the entry must be the same inode, else
    /// the upper inode is not in the index and the lookup gives `None`.
    fn lookup_index(&self, lower: &InodeRef, upper: Option<&InodeRef>) -> Result<Option<InodeRef>> {
        let (Some(dir), Some(name)) = (&self.index, index_name(lower)) else { return Ok(None) };
        let index = match dir.lookup(&name) {
            Ok(index) => index,
            Err(Errno::ENOENT) => return Ok(None),
            Err(e) => return Err(e),
        };
        // A whiteout in the index tells that all the lower hard links were removed.
        let kind = index.metadata().file_type();
        if is_whiteout(&index) || kind != lower.metadata().file_type() {
            return Err(Errno::EIO);
        }
        if upper.is_some_and(|upper| !same_inode(upper, &index)) {
            return Ok(None);
        }
        Ok(Some(index))
    }

    /// Gives the count of the links of the overlay file of the lower inode `lower` and of the
    /// upper inode `upper` in the index, from the attribute [`NLINK`], as `ovl_get_nlink` of
    /// Linux. It can be 0 or less after the removal of the last name. A lower inode with one
    /// link and an attribute that is not valid give `None`.
    fn nlink_value(&self, lower: &InodeRef, upper: &InodeRef) -> Option<i64> {
        let lower_links = lower.metadata().nlink;
        if lower_links == 1 {
            return None;
        }
        let value = upper.get_xattr(&self.xattr(NLINK)).ok()?;
        let (&base, diff) = value.split_first()?;
        let base = match base {
            b'L' => lower_links,
            b'U' => upper.metadata().nlink,
            _ => return None,
        };
        if !matches!(diff.first(), Some(b'+' | b'-')) {
            return None;
        }
        let diff: i64 = core::str::from_utf8(diff).ok()?.parse().ok()?;
        Some(i64::from(base) + diff)
    }

    /// Gives the count of the links of the overlay file of `lower` and `upper`, or `fallback`
    /// if [`Fs::nlink_value`] gives no count above 0.
    fn union_nlink(&self, lower: &InodeRef, upper: &InodeRef, fallback: u32) -> u32 {
        let value = self.nlink_value(lower, upper).filter(|&n| n > 0);
        value.and_then(|n| u32::try_from(n).ok()).unwrap_or(fallback)
    }

    /// Keeps `nlink`, the count of the links of the overlay file, in the attribute [`NLINK`] of
    /// the upper inode `upper` in the index, as `ovl_set_nlink_upper` of Linux. The value is
    /// the difference to the count of the links of `upper`, so a change of both counts by the
    /// same link keeps it correct.
    fn set_nlink(&self, upper: &InodeRef, nlink: u32) -> Result<()> {
        let diff = i64::from(nlink) - i64::from(upper.metadata().nlink);
        upper.set_xattr(&self.xattr(NLINK), format!("U{diff:+}").as_bytes(), 0)
    }

    /// Gives a new name for a temporary file in [`Fs::work`], as `ovl_lookup_temp` of Linux.
    fn temp_name(&self) -> Vec<u8> {
        format!("#{:x}", self.temp.fetch_add(1, Ordering::Relaxed)).into_bytes()
    }

    /// Makes a temporary file of the type `kind` in [`Fs::work`], and gives its name and inode.
    fn make_temp(&self, kind: FileType, perm: u32, rdev: u64) -> Result<(Vec<u8>, InodeRef)> {
        let work = self.work.as_ref().ok_or(Errno::EROFS)?;
        loop {
            let name = self.temp_name();
            match work.create(&name, kind, perm, rdev) {
                Ok(inode) => return Ok((name, inode)),
                Err(Errno::EEXIST) => continue,
                Err(e) => return Err(e),
            }
        }
    }

    /// Makes a whiteout of `name` in the upper directory `dir`, as `ovl_whiteout` of Linux. The
    /// whiteouts are links to one whiteout in [`Fs::work`], so they use one inode. A whiteout
    /// with too many links gives its place to a new one. If the upper file system cannot link
    /// the whiteout, each whiteout is a new inode.
    fn make_whiteout(&self, dir: &InodeRef, name: &[u8]) -> Result<()> {
        for _ in 0..2 {
            if self.no_shared_whiteout.load(Ordering::Relaxed) {
                break;
            }
            let mut slot = self.whiteout.lock();
            let shared = match slot.clone() {
                Some((_, inode)) => inode,
                None => match self.make_temp(FileType::CharDevice, 0, 0) {
                    Ok((temp, inode)) => {
                        *slot = Some((temp, inode.clone()));
                        inode
                    }
                    Err(_) => break,
                },
            };
            match dir.link(name, &shared) {
                Ok(()) => return Ok(()),
                // The temporary whiteout stays in the work directory until the next mount.
                Err(Errno::EMLINK) => *slot = None,
                Err(_) => self.no_shared_whiteout.store(true, Ordering::Relaxed),
            }
        }
        dir.create(name, FileType::CharDevice, 0, 0).map(|_| ())
    }

    /// Removes the entries of the index directory `dir` that are not correct, as
    /// `ovl_indexdir_cleanup` of Linux. A temporary file goes away. An entry whose lower inode
    /// is removed or has no overlay file goes away. Another error stops the mount.
    fn clean_index(&self, dir: &InodeRef) -> Result<()> {
        for entry in real_entries(dir)? {
            let index = match dir.lookup(&entry.name) {
                Ok(index) => index,
                Err(Errno::ENOENT) => continue,
                Err(e) => return Err(e),
            };
            if entry.name.starts_with(b"#") {
                remove_tree(dir, &entry.name, &index, 1)?;
                continue;
            }
            match self.verify_index(&entry.name, &index) {
                Ok(()) => {}
                Err(Errno::ESTALE | Errno::ENOENT) => remove_tree(dir, &entry.name, &index, 1)?,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Checks the entry `name` of the index directory, which is `index`, as `ovl_verify_index`
    /// of Linux. The name must be a file handle in hexadecimal. A whiteout and a directory stay.
    /// The attribute [`ORIGIN`] of the entry must be the same handle, and the lower inode must
    /// be there, else the check gives `ESTALE`. An entry with one link and no overlay file
    /// gives `ENOENT`.
    fn verify_index(&self, name: &[u8], index: &InodeRef) -> Result<()> {
        let fh = from_hex(name).filter(|fh| fh_is_valid(fh)).ok_or(Errno::EINVAL)?;
        let m = index.metadata();
        if is_whiteout(index) || m.is_dir() {
            return Ok(());
        }
        if index.get_xattr(&self.xattr(ORIGIN)).ok().as_deref() != Some(&fh[..]) {
            return Err(Errno::ESTALE);
        }
        let origin = self.decode_fh(&fh).ok_or(Errno::ESTALE)?;
        if m.nlink == 1 && self.union_nlink(&origin, index, 0) == 0 {
            return Err(Errno::ENOENT);
        }
        Ok(())
    }

    /// Sets the attribute [`IMPURE`] of the upper directory `dir`, as `ovl_set_impure` of Linux.
    fn set_impure(&self, dir: &InodeRef) -> Result<()> {
        let name = self.xattr(IMPURE);
        if dir.get_xattr(&name).is_ok() {
            return Ok(());
        }
        match dir.set_xattr(&name, b"y", 0) {
            Ok(()) | Err(Errno::EOPNOTSUPP) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Gives the device and the inode number that the upper inode `upper` of the lower inode
    /// `lower` shows. These are the numbers of the lower inode, or the numbers of the upper
    /// inode if another upper inode shows the numbers of the lower inode.
    fn ino_of(&self, lower: (u64, u64), upper: (u64, u64)) -> (u64, u64) {
        let mut inos = self.inos.lock();
        if *inos.entry(lower).or_insert(upper) == upper { lower } else { upper }
    }

    /// Finds the regular file at the absolute path `path` in the data-only layers, as
    /// `ovl_lookup_data_layers` of Linux. The top layer that has it wins.
    fn find_data(&self, path: &[u8]) -> Option<InodeRef> {
        'layers: for root in &self.data {
            let mut inode = root.clone();
            for name in path.split(|&b| b == b'/').filter(|n| !n.is_empty()) {
                if !inode.metadata().is_dir() {
                    continue 'layers;
                }
                match inode.lookup(name) {
                    Ok(next) => inode = next,
                    Err(_) => continue 'layers,
                }
            }
            if inode.metadata().file_type() == Some(FileType::Regular) {
                return Some(inode);
            }
        }
        None
    }

    /// Finds `name` in the directory `base` of a layer, as `ovl_lookup_single` of Linux.
    /// `prelen` is the size of the path in `walk.name` before `name`, and `post` is the path
    /// after `name`. A whiteout, an opaque directory and a file that is not a metacopy file
    /// stop the lookup. A redirect changes the path for the next layers.
    fn lookup_single(
        &self,
        base: &InodeRef,
        walk: &mut Walk,
        name: &[u8],
        prelen: usize,
        post: &[u8],
    ) -> Result<Option<InodeRef>> {
        let this = match base.lookup(name) {
            Ok(inode) => inode,
            Err(Errno::ENOENT | Errno::ENAMETOOLONG) => return Ok(None),
            Err(e) => return Err(e),
        };
        let last_element = post.is_empty();
        if self.is_whiteout_in(base, &this) {
            walk.stop = true;
            return Ok(None);
        }
        let m = this.metadata();
        // A metacopy file finds its data only in a regular file.
        if last_element && walk.metacopy && m.file_type() != Some(FileType::Regular) {
            walk.stop = true;
            return Ok(None);
        }
        if m.is_dir() {
            walk.is_dir |= last_element;
            if walk.last {
                return Ok(Some(this));
            }
            if self.is_opaque(&this) {
                walk.stop = true;
                return Ok(Some(this));
            }
        } else {
            if walk.is_dir || !last_element {
                walk.stop = true;
                return Ok(None);
            }
            walk.metacopy = self.is_metacopy(&this);
            walk.stop = !walk.metacopy;
            if !walk.metacopy || walk.last {
                return Ok(Some(this));
            }
        }
        if let Some(redirect) = self.redirect_of(&this)? {
            let mut path = if redirect[0] == b'/' {
                walk.absolute = true;
                // An absolute redirect below an opaque directory starts the lookup again.
                walk.stop = false;
                redirect
            } else {
                [&walk.name[..prelen], &redirect[..]].concat()
            };
            path.extend_from_slice(post);
            walk.name.clone_from(&path);
            walk.redirect = Some(path);
        }
        Ok(Some(this))
    }

    /// Finds `walk.name` in the directory `base` of a layer, as `ovl_lookup_layer` of Linux.
    /// The lookup of an absolute path starts at `base`, the root of the layer, and finds one
    /// name at a time.
    fn lookup_layer(&self, base: &InodeRef, walk: &mut Walk) -> Result<Option<InodeRef>> {
        if walk.name.first() != Some(&b'/') {
            let name = walk.name.clone();
            return self.lookup_single(base, walk, &name, 0, b"");
        }
        let mut dir = base.clone();
        // The size of the path after the next slash. A redirect changes the path before the
        // next name, but not the path after it.
        let mut rem = walk.name.len() - 1;
        loop {
            let start = walk.name.len() - rem;
            let rest = walk.name[start..].to_vec();
            let len = rest.iter().position(|&b| b == b'/').unwrap_or(rest.len());
            let (name, post) = rest.split_at(len);
            let Some(next) = self.lookup_single(&dir, walk, name, start, post)? else {
                return Ok(None);
            };
            if post.is_empty() {
                return Ok(Some(next));
            }
            dir = next;
            rem -= len + 1;
        }
    }
}

/// The state of the lookup of a name in the layers, as `struct ovl_lookup_data` of Linux.
#[derive(Default)]
struct Walk {
    /// The name, or the absolute path from the root of a layer, to find in the next layer.
    name: Vec<u8>,
    /// The lookup found a directory.
    is_dir: bool,
    /// The lookup does not look in the next layers.
    stop: bool,
    /// The next layer is the last layer for the lookup, so it does not read the attributes
    /// that tell about the layers below.
    last: bool,
    /// The path of the last redirect that the lookup found.
    redirect: Option<Vec<u8>>,
    /// The lookup found an absolute redirect.
    absolute: bool,
    /// The last file that the lookup found is a metacopy file.
    metacopy: bool,
}

/// Makes a new overlayfs for `mount(2)`. The options are `lowerdir=`, or `lowerdir+=` and
/// `datadir+=`, then `upperdir=`, `workdir=`, `userxattr`, `redirect_dir=`, `metacopy=`,
/// `index=` and `uuid=`. The upper directory needs the work directory, as in Linux. The mount
/// makes the directory `work` in the work directory. If it cannot, the mount does not accept
/// changes, as Linux.
///
/// An upper or work directory that another mount uses gives `EBUSY` with the option `index`,
/// as Linux. Without it, the mount continues.
pub fn mount(args: &MountArgs<'_>) -> Result<InodeRef> {
    let mut opts = Options::parse(args.data)?;
    let lowers = opts.lowers.iter().map(|p| dir(args, p)).collect::<Result<Vec<_>>>()?;
    let data = opts.data.iter().map(|p| dir(args, p)).collect::<Result<Vec<_>>>()?;
    let mut in_use = InUse::default();
    let (upper, work_dir) = match (&opts.upper, &opts.work) {
        (Some(upper), Some(work)) => {
            let upper = dir(args, upper)?;
            let work = dir(args, work)?;
            // Linux refuses an upper directory on overlayfs, because overlayfs cannot keep
            // its whiteouts and attributes there.
            if upper.fs_id() != work.fs_id() || upper.fs_magic() == OVERLAYFS_SUPER_MAGIC {
                return Err(Errno::EINVAL);
            }
            // The upper directory first, then the work directory, as `ovl_get_upper` and
            // `ovl_get_workdir` of Linux.
            for dir in [&upper, &work] {
                if !in_use.take(dir) && opts.index {
                    return Err(Errno::EBUSY);
                }
            }
            (Some(upper), Some(work))
        }
        (None, _) => (None, None),
        (Some(_), None) => return Err(Errno::EINVAL),
    };
    let work = work_dir.as_ref().and_then(|w| make_dir(w, WORK, false).ok());
    let mut writable = work.is_some();
    let prefix = if opts.userxattr { USER } else { TRUSTED };
    // The option `index` needs an upper directory, as Linux.
    opts.index &= writable;
    let mut index = None;
    if let (true, Some(root), Some(work_dir), Some(lower)) =
        (opts.index, &upper, &work_dir, lowers.first())
    {
        match make_index(prefix, work_dir, root, lower)? {
            IndexDir::Made(dir) => index = Some(dir),
            // The layers have no file handles, so the mount continues without the index.
            IndexDir::NoHandles => opts.index = false,
            // The mount with no index directory does not accept changes, as Linux.
            IndexDir::Failed => writable = false,
        }
    }
    let dev = rk_vfs::anon_dev();
    let uuid = match &upper {
        Some(root) if writable => init_uuid(root, prefix, &mut opts.uuid, dev),
        Some(root) => read_uuid(root, prefix, &mut opts.uuid),
        None => None,
    };
    let real = upper.clone().or_else(|| lowers.first().cloned()).ok_or(Errno::EINVAL)?;
    // The id of a mount with a uuid comes from the uuid, as `uuid_to_fsid` of Linux. Else it
    // is the id of the file system of the real root.
    let fsid = uuid.map_or_else(|| real.fs_fsid(), |u| fold(&u[..8]) ^ fold(&u[8..]));
    let upper_acl = upper.as_ref().is_some_and(|u| u.posix_acl());
    let fs = Fs {
        dev,
        writable,
        upper_acl,
        read_only: AtomicBool::new(!writable || args.read_only),
        prefix,
        options: opts.show(),
        roots: lowers.into_iter().enumerate().collect(),
        data,
        redirect: opts.redirect,
        metacopy: opts.metacopy,
        fsid,
        inos: SpinLock::new(BTreeMap::new()),
        cache: Cache::default(),
        // The index directory is also the directory for the temporary files, as Linux.
        work: index.clone().or(work),
        index,
        indexed: AtomicU64::new(0),
        whiteout: SpinLock::new(None),
        no_shared_whiteout: AtomicBool::new(false),
        temp: AtomicU64::new(0),
        _in_use: in_use,
    };
    if let Some(dir) = &fs.index {
        fs.clean_index(dir)?;
    }
    Node::root(Arc::new(fs), upper)
}

/// The result of [`make_index`].
enum IndexDir {
    /// The index directory.
    Made(InodeRef),
    /// A layer has no file handles, so the mount has no index.
    NoHandles,
    /// The mount cannot make the index directory.
    Failed,
}

/// Makes the index directory `index` in the work directory `work_dir`, or keeps the directory
/// that is there, as `ovl_get_indexdir` of Linux. The upper root `upper` must have the
/// attribute [`ORIGIN`] with the file handle of the root `lower` of the top lower layer, and
/// the index directory must have the attribute [`UPPER`] with the file handle of the upper
/// root. A new directory gets them. A different handle gives `ESTALE`, because the index is for
/// other layers.
fn make_index(
    prefix: &[u8],
    work_dir: &InodeRef,
    upper: &InodeRef,
    lower: &InodeRef,
) -> Result<IndexDir> {
    let (Some(lower_fh), Some(upper_fh)) = (encode_fh(lower), encode_fh(upper)) else {
        return Ok(IndexDir::NoHandles);
    };
    verify_fh(upper, &[prefix, ORIGIN].concat(), &lower_fh)?;
    let Ok(index) = make_dir(work_dir, INDEX, true) else { return Ok(IndexDir::Failed) };
    verify_fh(&index, &[prefix, UPPER].concat(), &upper_fh)?;
    Ok(IndexDir::Made(index))
}

/// Checks that the attribute `name` of `inode` is the file handle `fh`, as
/// `ovl_verify_set_fh` of Linux. An inode without the attribute gets it. Another handle gives
/// `ESTALE`.
fn verify_fh(inode: &InodeRef, name: &[u8], fh: &[u8]) -> Result<()> {
    match inode.get_xattr(name) {
        Ok(value) if value == fh => Ok(()),
        Ok(_) => Err(Errno::ESTALE),
        Err(Errno::ENODATA) => inode.set_xattr(name, fh, 0),
        Err(e) => Err(e),
    }
}

/// Gives the file handle of `inode` in the format of the attribute [`ORIGIN`], as
/// `ovl_encode_real_fh` of Linux, or `None` for a file system without file handles.
fn encode_fh(inode: &InodeRef) -> Option<Vec<u8>> {
    let (ty, words) = inode.file_handle()?;
    let ty = u8::try_from(ty).ok()?;
    let size = u8::try_from(FH_HEADER + words.len() * 4).ok()?;
    // The uuid has the id of the file system in its first 8 bytes.
    let mut fh = vec![0, FH_MAGIC, size, 0, ty];
    fh.extend_from_slice(&inode.fs_id().to_le_bytes());
    fh.extend_from_slice(&[0; 8]);
    for word in words {
        fh.extend_from_slice(&word.to_le_bytes());
    }
    Some(fh)
}

/// Tells if `fh` has the format of the attribute [`ORIGIN`], as `ovl_check_fb_len` of Linux.
fn fh_is_valid(fh: &[u8]) -> bool {
    fh.len() >= FH_HEADER
        && fh[..2] == [0, FH_MAGIC]
        && usize::from(fh[2]) == fh.len()
        && (fh.len() - FH_HEADER).is_multiple_of(4)
}

/// Gives the name of the entry of the lower inode `lower` in the index directory: its file
/// handle in lowercase hexadecimal, as `ovl_get_index_name` of Linux.
fn index_name(lower: &InodeRef) -> Option<Vec<u8>> {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let fh = encode_fh(lower)?;
    Some(
        fh.iter()
            .flat_map(|&b| [DIGITS[usize::from(b >> 4)], DIGITS[usize::from(b & 15)]])
            .collect(),
    )
}

/// Gives the bytes of the lowercase hexadecimal name `name`, or `None` if it is not one.
fn from_hex(name: &[u8]) -> Option<Vec<u8>> {
    let digit = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let (pairs, rest) = name.as_chunks::<2>();
    if !rest.is_empty() {
        return None;
    }
    pairs.iter().map(|&[hi, lo]| Some((digit(hi)? << 4) | digit(lo)?)).collect()
}

/// Tells if `a` and `b` are the same inode.
fn same_inode(a: &InodeRef, b: &InodeRef) -> bool {
    if Arc::ptr_eq(a, b) {
        return true;
    }
    let (a, b) = (a.metadata(), b.metadata());
    (a.dev, a.ino) == (b.dev, b.ino)
}

/// Gives the 8 bytes of `bytes` as a number, the first byte last.
fn fold(bytes: &[u8]) -> u64 {
    bytes.iter().rev().fold(0, |n, &b| (n << 8) | u64::from(b))
}

/// Gives the uuid that the attribute [`UUID`] of the upper root `root` keeps, for a mount that
/// cannot change the upper root. A root without a uuid changes `mode` to `uuid=null`.
fn read_uuid(root: &InodeRef, prefix: &[u8], mode: &mut Uuid) -> Option<[u8; 16]> {
    if matches!(*mode, Uuid::Off | Uuid::Null) {
        return None;
    }
    let uuid = root.get_xattr(&[prefix, UUID].concat()).ok().and_then(|v| v.try_into().ok());
    if uuid.is_none() {
        *mode = Uuid::Null;
    }
    uuid
}

/// Gives the uuid of the overlay with the upper root `root`, as `ovl_init_uuid_xattr` of
/// Linux. The attribute [`UUID`] of the upper root keeps it. With `uuid=auto`, an old overlay
/// gets `uuid=null`, and a new overlay gets `uuid=on`. An old overlay has an upper root with
/// the attribute [`IMPURE`] but without a uuid. With `uuid=on`, the mount makes a uuid if the
/// root does not have one. An error gives `uuid=null`.
fn init_uuid(root: &InodeRef, prefix: &[u8], mode: &mut Uuid, dev: u64) -> Option<[u8; 16]> {
    if matches!(*mode, Uuid::Off | Uuid::Null) {
        return None;
    }
    let name = [prefix, UUID].concat();
    match root.get_xattr(&name) {
        Ok(value) if value.len() == 16 => return value.try_into().ok(),
        Err(Errno::ENODATA) => {}
        _ => {
            *mode = Uuid::Null;
            return None;
        }
    }
    if *mode == Uuid::Auto {
        if root.get_xattr(&[prefix, IMPURE].concat()).is_ok() {
            *mode = Uuid::Null;
            return None;
        }
        *mode = Uuid::On;
    }
    let mut uuid = [0u8; 16];
    uuid[..8].copy_from_slice(&rk_frame::arch::random_seed().to_le_bytes());
    let low = rk_frame::arch::random_seed() ^ dev.rotate_left(32);
    uuid[8..].copy_from_slice(&low.to_le_bytes());
    // A uuid of version 4 and of the variant of RFC 4122, as `uuid_gen` of Linux.
    uuid[6] = (uuid[6] & 0x0f) | 0x40;
    uuid[8] = (uuid[8] & 0x3f) | 0x80;
    if root.set_xattr(&name, &uuid, 0).is_err() {
        *mode = Uuid::Null;
        return None;
    }
    Some(uuid)
}

/// Makes the directory `name` in the work directory `work_dir`, with the mode 0 and with no ACL,
/// as `ovl_workdir_create` of Linux, and gives it. It first removes an old `name`. With
/// `persist`, it keeps an old directory, as for the index directory.
fn make_dir(work_dir: &InodeRef, name: &[u8], persist: bool) -> Result<InodeRef> {
    // The VFS checks the flags for a change through a system call. The mount changes the work
    // directory directly, so it checks the flags here.
    check_immutable(&**work_dir)?;
    match work_dir.lookup(name) {
        Ok(old) if persist && old.metadata().is_dir() => return Ok(old),
        Ok(old) => remove_tree(work_dir, name, &old, 0)?,
        Err(Errno::ENOENT) => {}
        Err(e) => return Err(e),
    }
    let dir = work_dir.create(name, FileType::Directory, 0, 0)?;
    for name in [acl::DEFAULT, acl::ACCESS] {
        match dir.remove_xattr(name) {
            Ok(()) | Err(Errno::ENODATA | Errno::EOPNOTSUPP) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(dir)
}

/// Removes `name`, which is `inode`, from `dir`, with its entries. As `ovl_workdir_cleanup` of
/// Linux, it does not go deeper than two levels below `work`, and then gives `EINVAL`.
fn remove_tree(dir: &InodeRef, name: &[u8], inode: &InodeRef, level: u32) -> Result<()> {
    if !inode.metadata().is_dir() {
        return dir.unlink(name);
    }
    if level > 2 {
        return Err(Errno::EINVAL);
    }
    for entry in real_entries(inode)? {
        let child = inode.lookup(&entry.name)?;
        remove_tree(inode, &entry.name, &child, level + 1)?;
    }
    dir.rmdir(name)
}

/// Finds the directory at `path` for an option.
fn dir(args: &MountArgs<'_>, path: &[u8]) -> Result<InodeRef> {
    let inode = args.lookup(path)?;
    if !inode.metadata().is_dir() {
        return Err(Errno::ENOTDIR);
    }
    Ok(inode)
}

/// Makes a new overlayfs of the directories `lowers`, the top layer first, and `upper`, and
/// gives its root. Gives `EINVAL` if there is no directory. The mount does not use a work
/// directory, has the default features, and has no options for `/proc/PID/mountinfo`.
pub fn new(lowers: Vec<InodeRef>, upper: Option<InodeRef>) -> Result<InodeRef> {
    let real = upper.clone().or_else(|| lowers.first().cloned()).ok_or(Errno::EINVAL)?;
    let fs = Arc::new(Fs {
        dev: rk_vfs::anon_dev(),
        writable: upper.is_some(),
        upper_acl: upper.as_ref().is_some_and(|u| u.posix_acl()),
        read_only: AtomicBool::new(upper.is_none()),
        prefix: TRUSTED,
        options: Vec::new(),
        cache: Cache::default(),
        roots: lowers.into_iter().enumerate().collect(),
        data: Vec::new(),
        redirect: Redirect::Follow,
        metacopy: false,
        fsid: real.fs_fsid(),
        inos: SpinLock::new(BTreeMap::new()),
        index: None,
        indexed: AtomicU64::new(0),
        work: None,
        whiteout: SpinLock::new(None),
        no_shared_whiteout: AtomicBool::new(false),
        temp: AtomicU64::new(0),
        _in_use: InUse::default(),
    });
    Node::root(fs, upper)
}

/// Tells if `inode` is a whiteout: a character device with the device number 0:0.
fn is_whiteout(inode: &InodeRef) -> bool {
    let m = inode.metadata();
    m.file_type() == Some(FileType::CharDevice) && m.rdev == 0
}

/// Gives each entry of the directory `inode` but `.` and `..`.
fn real_entries(inode: &InodeRef) -> Result<Vec<DirEntry>> {
    let mut out = Vec::new();
    let mut pos = 0;
    while let Some((entry, next)) = inode.read_dir(pos)? {
        if entry.name != b"." && entry.name != b".." {
            out.push(entry);
        }
        pos = next;
    }
    Ok(out)
}

/// The inodes in the layers that a lookup found for a node.
#[derive(Default)]
struct Found {
    upper: Option<InodeRef>,
    /// The lower inodes with the positions of their layers, the top layer first.
    lowers: Vec<(usize, InodeRef)>,
    /// The attribute [`REDIRECT`] of the upper inode.
    redirect: Option<Vec<u8>>,
    /// The upper inode, or else the top lower inode, is a metacopy file.
    metacopy: bool,
    /// The lower inode with the data of a regular file.
    lowerdata: Option<InodeRef>,
    /// The upper inode is the entry of the lower inode in the index directory.
    indexed: bool,
    /// The entry of the lower inode in the index directory, for a node without an upper inode.
    index: Option<InodeRef>,
}

/// An inode of overlayfs: one name with its inodes in the layers.
struct Node {
    fs: Arc<Fs>,
    this: Weak<Node>,
    /// The directory of the node and the name in it. The root has no parent.
    place: SpinLock<(Option<Arc<Node>>, Vec<u8>)>,
    /// The inode in the upper directory, after a copy up or for a new file.
    upper: SpinLock<Option<InodeRef>>,
    /// The inode that the node had first: the upper inode, or else the top lower inode.
    first: InodeRef,
    /// The node had an upper inode when the lookup made it.
    from_upper: bool,
    /// The inodes in the lower directories that the node shows, with the positions of their
    /// layers, the top layer first. A file that is not a directory has one at most: the top
    /// lower inode, or the origin of the upper inode.
    lowers: Vec<(usize, InodeRef)>,
    /// The attribute [`REDIRECT`] of the upper inode.
    redirect: SpinLock<Option<Vec<u8>>>,
    /// The upper inode, or else the top lower inode, is a metacopy file. The data is then in
    /// `lowerdata`.
    metacopy: AtomicBool,
    /// The lower inode with the data of a regular file. A metacopy file without data in the
    /// data-only layers has `None`.
    lowerdata: Option<InodeRef>,
    /// The upper inode is the entry of the lower inode in the index directory, so the other
    /// lower hard links of the lower inode show it too.
    indexed: AtomicBool,
    /// For a node without an upper inode, the entry of the lower inode in the index directory,
    /// which a copy up of another lower hard link made. It is correct while the count
    /// [`Fs::indexed`] has the first value.
    index: SpinLock<(u64, Option<InodeRef>)>,
    /// The nodes that a lookup in this directory gave, so a name keeps one node while it is in
    /// use.
    children: SpinLock<BTreeMap<Vec<u8>, Weak<Node>>>,
    /// The children that are not in use, as the unused dentries of Linux. A lookup gives the
    /// same node again, with the same inodes of the layers, until a removal or an eviction.
    unused: SpinLock<BTreeMap<Vec<u8>, Saved>>,
    /// The joined entries of the directory, which `read_dir` makes again at position 0.
    entries: SpinLock<Vec<DirEntry>>,
}

impl Node {
    fn new(
        fs: &Arc<Fs>,
        parent: Option<Arc<Node>>,
        name: Vec<u8>,
        found: Found,
    ) -> Option<Arc<Node>> {
        let first = found.upper.clone().or_else(|| found.lowers.first().map(|l| l.1.clone()))?;
        let stamp = fs.indexed.load(Ordering::Acquire);
        Some(Arc::new_cyclic(|this| Node {
            fs: fs.clone(),
            first,
            from_upper: found.upper.is_some(),
            this: this.clone(),
            place: SpinLock::new((parent, name)),
            upper: SpinLock::new(found.upper),
            lowers: found.lowers,
            redirect: SpinLock::new(found.redirect),
            metacopy: AtomicBool::new(found.metacopy),
            lowerdata: found.lowerdata,
            indexed: AtomicBool::new(found.indexed),
            index: SpinLock::new((stamp, found.index)),
            children: SpinLock::new(BTreeMap::new()),
            unused: SpinLock::new(BTreeMap::new()),
            entries: SpinLock::new(Vec::new()),
        }))
    }

    /// Makes the node of `name` again from the unused node `saved`.
    fn restore(self: &Arc<Self>, name: &[u8], saved: Saved) -> Arc<Node> {
        let node = Arc::new_cyclic(|this| Node {
            fs: self.fs.clone(),
            first: saved.first,
            from_upper: saved.from_upper,
            this: this.clone(),
            place: SpinLock::new((Some(self.clone()), name.to_vec())),
            upper: SpinLock::new(saved.upper),
            lowers: saved.lowers,
            redirect: SpinLock::new(saved.redirect),
            metacopy: AtomicBool::new(saved.metacopy),
            lowerdata: saved.lowerdata,
            indexed: AtomicBool::new(saved.indexed),
            // The node looks in the index directory again.
            index: SpinLock::new((u64::MAX, None)),
            children: SpinLock::new(BTreeMap::new()),
            unused: SpinLock::new(saved.unused),
            entries: SpinLock::new(Vec::new()),
        });
        // The unused children of the node can go away again in an eviction.
        let names: Vec<_> = node.unused.lock().iter().map(|(n, s)| (n.clone(), s.stamp)).collect();
        let mut lru = self.fs.cache.lru.lock();
        for (n, stamp) in names {
            lru.push_back((node.this.clone(), n, stamp));
        }
        node
    }

    /// Makes the root of the mount `fs` with the upper root `upper`. Gives `EINVAL` if there is
    /// no directory.
    fn root(fs: Arc<Fs>, upper: Option<InodeRef>) -> Result<InodeRef> {
        let found = Found { upper, lowers: fs.roots.clone(), ..Found::default() };
        let node = Node::new(&fs, None, Vec::new(), found).ok_or(Errno::EINVAL)?;
        Ok(node)
    }

    /// Gives the reference to this node. A node is alive while a caller uses it.
    fn arc(&self) -> Result<Arc<Node>> {
        self.this.upgrade().ok_or(Errno::ENOENT)
    }

    fn upper(&self) -> Option<InodeRef> {
        self.upper.lock().clone()
    }

    /// The inode that gives the attributes: the upper inode, the entry in the index directory,
    /// or else the top lower inode.
    fn real(&self) -> InodeRef {
        self.upper().or_else(|| self.index_inode()).unwrap_or_else(|| self.first.clone())
    }

    /// Gives the entry of the lower inode in the index directory for a node without an upper
    /// inode. After a change of the index directory, it looks in it again, so a copy up of
    /// another lower hard link shows here.
    fn index_inode(&self) -> Option<InodeRef> {
        self.fs.index.as_ref()?;
        let lower = self.top()?;
        let stamp = self.fs.indexed.load(Ordering::Acquire);
        let mut slot = self.index.lock();
        if slot.0 != stamp {
            let m = lower.metadata();
            let linked = !m.is_dir() && m.nlink > 1;
            slot.1 = if linked { self.fs.lookup_index(lower, None).ok().flatten() } else { None };
            slot.0 = stamp;
        }
        slot.1.clone()
    }

    /// Gives the upper inode in the index directory that keeps the count of the links of the
    /// overlay file: the upper inode of an indexed node, or the entry of a node without an
    /// upper inode.
    fn index_upper(&self) -> Option<InodeRef> {
        match self.upper() {
            Some(upper) => self.indexed.load(Ordering::Acquire).then_some(upper),
            None => self.index_inode(),
        }
    }

    /// Tells if a copy up of the file puts it in the index directory, as `ovl_need_index` of
    /// Linux: the option `index` is on, and the lower inode is a hard link that is not a
    /// directory.
    fn needs_index(&self) -> bool {
        self.fs.index.is_some()
            && self.top().is_some_and(|lower| {
                let m = lower.metadata();
                !m.is_dir() && m.nlink > 1
            })
    }

    /// The top lower inode.
    fn top(&self) -> Option<&InodeRef> {
        self.lowers.first().map(|(_, inode)| inode)
    }

    fn is_metacopy(&self) -> bool {
        self.metacopy.load(Ordering::Acquire)
    }

    /// The inode that gives the data: the real inode, or the lower inode with the data of a
    /// metacopy file. A metacopy file without its data gives `ENOENT`, as Linux.
    fn data(&self) -> Result<InodeRef> {
        if !self.is_metacopy() {
            return Ok(self.real());
        }
        self.lowerdata.clone().ok_or(Errno::ENOENT)
    }

    fn is_dir(&self) -> bool {
        self.real().metadata().is_dir()
    }

    /// Gives the device and the inode number of the node, as `ovl_getattr` of Linux. A copy up
    /// does not change them, so a lock on the file stays the same lock. A node with an upper
    /// inode and a lower inode shows the numbers of the lower inode, so the numbers stay the
    /// same after a new mount. Without the option `index`, a lower hard link is not one inode
    /// after a copy up, so its upper inode shows its own numbers. With it, the upper inode in
    /// the index directory shows the numbers of the lower inode.
    fn identity(&self) -> (u64, u64) {
        let first = self.first.metadata();
        let own = (first.dev, first.ino);
        if !self.from_upper {
            return own;
        }
        let Some(lower) = self.top() else { return own };
        let m = lower.metadata();
        if self.indexed.load(Ordering::Acquire) {
            return (m.dev, m.ino);
        }
        if !m.is_dir() && m.nlink > 1 {
            return own;
        }
        self.fs.ino_of((m.dev, m.ino), own)
    }

    /// Gives the node of `inode` if it is a node of this mount.
    fn same_fs(&self, inode: &InodeRef) -> Result<Arc<Node>> {
        let any: &dyn Any = &**inode;
        let node = any.downcast_ref::<Node>().ok_or(Errno::EXDEV)?;
        if !Arc::ptr_eq(&node.fs, &self.fs) {
            return Err(Errno::EXDEV);
        }
        node.arc()
    }

    /// Gives `EROFS` if the mount has no upper directory.
    fn check_writable(&self) -> Result<()> {
        if self.fs.writable { Ok(()) } else { Err(Errno::EROFS) }
    }

    /// Gives `EOPNOTSUPP` for a change of the ACL `name` if the upper layer has no POSIX ACLs,
    /// as `ovl_set_acl` of Linux. The check comes before the copy up.
    fn check_acl(&self, name: &[u8]) -> Result<()> {
        if acl::is_name(name) && !self.fs.upper_acl { Err(Errno::EOPNOTSUPP) } else { Ok(()) }
    }

    /// Finds `name` in the layers of this directory, and gives a new node for it, as
    /// `ovl_lookup` of Linux. A directory joins the directories below it until a layer has a
    /// file that is not a directory, a whiteout or an opaque directory. A redirect changes the
    /// name for the lower layers. An absolute redirect starts the lookup again at the roots of
    /// the layers below. A metacopy file finds its data below it, or in the data-only layers
    /// through an absolute redirect.
    fn find(&self, name: &[u8]) -> Result<Arc<Node>> {
        let fs = &self.fs;
        let mut walk = Walk { name: name.to_vec(), ..Walk::default() };
        walk.last = !fs.follow() && self.lowers.is_empty();
        let mut stack = &self.lowers[..];
        let mut upper = None;
        let mut upper_meta = false;
        let mut redirect = None;
        // The lookup goes to the roots of the layers once at most.
        let mut at_roots = false;
        if let Some(dir) = self.upper() {
            if fs.is_opaque(&dir) {
                stack = &[];
            }
            upper = fs.lookup_layer(&dir, &mut walk)?;
            upper_meta = upper.is_some() && !walk.is_dir && walk.metacopy;
            if let Some(path) = &walk.redirect {
                if path[0] == b'/' {
                    stack = &fs.roots;
                    at_roots = true;
                }
                redirect = Some(path.clone());
            }
        }
        let mut lowers: Vec<(usize, InodeRef)> = Vec::new();
        let mut i = 0;
        while !walk.stop && i < stack.len() {
            let (layer, base) = (stack[i].0, stack[i].1.clone());
            if !fs.follow() {
                walk.last = i == stack.len() - 1;
            } else if walk.is_dir || fs.data.is_empty() {
                walk.last = layer == fs.roots.len() - 1;
            }
            i += 1;
            let Some(this) = fs.lookup_layer(&base, &mut walk)? else { continue };
            if (upper_meta || walk.metacopy) && !fs.metacopy {
                return Err(Errno::EIO);
            }
            if walk.is_dir
                && lowers.is_empty()
                && let Some(upper) = &upper
            {
                self.fix_origin(upper, &this);
            }
            // A metacopy file keeps the top lower inode and the inode with the data, but not
            // the metacopy files between them.
            if !walk.metacopy || lowers.is_empty() {
                lowers.push((layer, this));
            }
            if walk.redirect.is_some() && !fs.follow() {
                return Err(Errno::EPERM);
            }
            if walk.stop {
                break;
            }
            if !at_roots && walk.redirect.as_ref().is_some_and(|p| p[0] == b'/') {
                at_roots = true;
                stack = &fs.roots;
                i = layer + 1;
            }
        }
        let mut lowerdata = None;
        let mut metacopy = upper_meta;
        if walk.metacopy && !lowers.is_empty() && !fs.data.is_empty() && walk.absolute {
            // The data is in a data-only layer. Without it, the file has the attributes but no
            // data, as the lazy lookup of Linux.
            walk.metacopy = false;
            lowerdata = walk.redirect.as_deref().and_then(|path| fs.find_data(path));
            metacopy |= upper.is_none();
        } else if !walk.is_dir {
            if lowers.is_empty()
                && let Some(origin) = upper.as_ref().and_then(|u| fs.origin(u))
            {
                lowers.push((0, origin));
            } else {
                lowerdata = lowers.last().map(|(_, inode)| inode.clone());
                metacopy |= upper.is_none() && lowers.len() > 1;
            }
        }
        if walk.metacopy || (upper_meta && lowers.is_empty()) {
            return Err(Errno::EIO);
        }
        if upper.is_none() && lowers.is_empty() {
            return Err(Errno::ENOENT);
        }
        if !walk.is_dir {
            lowers.truncate(1);
        }
        let (mut indexed, mut index) = (false, None);
        if !walk.is_dir
            && let Some((_, origin)) = lowers.first()
        {
            let linked = upper.is_some() || origin.metadata().nlink > 1;
            let entry = if linked { fs.lookup_index(origin, upper.as_ref())? } else { None };
            indexed = entry.is_some() && upper.is_some();
            if upper.is_none() {
                index = entry;
            }
        }
        let found = Found { upper, lowers, redirect, metacopy, lowerdata, indexed, index };
        Node::new(&self.fs, Some(self.arc()?), name.to_vec(), found).ok_or(Errno::ENOENT)
    }

    /// Sets the attribute [`ORIGIN`] of the upper directory `upper` of a merged directory to the
    /// lower directory `lower` if it does not have one, and marks this directory as impure, as
    /// `ovl_fix_origin` of Linux. An error does not stop the lookup.
    fn fix_origin(&self, upper: &InodeRef, lower: &InodeRef) {
        if !self.fs.writable || upper.get_xattr(&self.fs.xattr(ORIGIN)).is_ok() {
            return;
        }
        if self.fs.set_origin(upper, lower) == Ok(true)
            && let Some(dir) = self.upper()
        {
            let _ = self.fs.set_impure(&dir);
        }
    }

    /// Gives the node of `name`, from the nodes in use or the unused nodes if one has the name.
    fn child(&self, name: &[u8]) -> Result<Arc<Node>> {
        if let Some(node) = self.children.lock().get(name).and_then(Weak::upgrade) {
            return Ok(node);
        }
        let saved = self.unused.lock().remove(name);
        let node = match saved {
            Some(saved) => self.arc()?.restore(name, saved),
            None => self.find(name)?,
        };
        let mut children = self.children.lock();
        if let Some(old) = children.get(name).and_then(Weak::upgrade) {
            return Ok(old);
        }
        children.retain(|_, w| w.strong_count() > 0);
        children.insert(name.to_vec(), Arc::downgrade(&node));
        Ok(node)
    }

    /// Forgets the node of `name` after a change of the directory.
    fn forget(&self, name: &[u8]) {
        self.children.lock().remove(name);
        let old = self.unused.lock().remove(name);
        drop(old);
    }

    /// Keeps the node `saved` of `name` that is not in use, and evicts the oldest unused nodes
    /// of the mount if there are too many.
    fn keep(&self, name: Vec<u8>, saved: Saved) {
        let stamp = saved.stamp;
        let old = self.unused.lock().insert(name.clone(), saved);
        drop(old);
        self.fs.cache.lru.lock().push_back((self.this.clone(), name, stamp));
    }

    /// Checks that the node `node` of `name` still has the same inode in the upper directory
    /// `dir`, as `ovl_remove_upper` and `ovl_remove_and_whiteout` of Linux. A node without an
    /// upper inode must not have a file in the upper directory. A change of the upper directory
    /// that is not through the mount gives `ESTALE`.
    fn check_upper(dir: &InodeRef, name: &[u8], node: &Node) -> Result<()> {
        let real = match dir.lookup(name) {
            Ok(i) if !is_whiteout(&i) => Some(i),
            Ok(_) | Err(Errno::ENOENT) => None,
            Err(e) => return Err(e),
        };
        let same = match (node.upper(), real) {
            (None, None) => true,
            (Some(upper), Some(real)) => {
                let (a, b) = (upper.metadata(), real.metadata());
                Arc::ptr_eq(&upper, &real) || (a.dev, a.ino) == (b.dev, b.ino)
            }
            _ => false,
        };
        if same { Ok(()) } else { Err(Errno::ESTALE) }
    }

    /// Tells if a lower directory of this directory shows `name`. A removal of such a name needs
    /// a whiteout.
    fn lower_has(&self, name: &[u8]) -> bool {
        for (_, dir) in &self.lowers {
            match dir.lookup(name) {
                Ok(i) => return !self.fs.is_whiteout_in(dir, &i),
                Err(_) => continue,
            }
        }
        false
    }

    /// Copies the file to the upper directory if it is not there, with its parents, and gives
    /// the upper inode. With the option `metacopy`, a regular file gets only its attributes.
    fn copy_up(&self) -> Result<InodeRef> {
        self.copy_up_with(false)
    }

    /// Copies the file to the upper directory if it is not there, with its parents, and gives
    /// the upper inode, as `ovl_copy_up_flags` of Linux. A regular file gets its data with
    /// `data` or without the option `metacopy`. Else it gets only the attributes and the
    /// attribute [`METACOPY`], and a later call with `data` copies the data. The upper inode
    /// gets the attribute [`ORIGIN`], and the upper parent gets the attribute [`IMPURE`].
    ///
    /// With the option `index`, a lower hard link goes to the index directory first, and the
    /// upper directory gets a link to it, as `ovl_link_up` of Linux. A copy up of another lower
    /// hard link of the same lower inode then only makes a link.
    fn copy_up_with(&self, data: bool) -> Result<InodeRef> {
        if let Some(upper) = self.upper() {
            if data && self.is_metacopy() {
                self.copy_data_up(&upper)?;
            }
            return Ok(upper);
        }
        self.check_writable()?;
        let (parent, name) = self.place.lock().clone();
        // The root always has an upper inode on a writable mount.
        let dir = parent.ok_or(Errno::EROFS)?.copy_up()?;
        let lower = self.top().ok_or(Errno::ENOENT)?.clone();
        let mut slot = self.upper.lock();
        if let Some(upper) = slot.clone() {
            return Ok(upper);
        }
        match dir.lookup(&name) {
            Ok(i) if is_whiteout(&i) => dir.unlink(&name)?,
            Ok(i) => {
                *slot = Some(i.clone());
                return Ok(i);
            }
            Err(Errno::ENOENT) => {}
            Err(e) => return Err(e),
        }
        let m = lower.metadata();
        let kind = m.file_type().ok_or(Errno::EIO)?;
        let indexed = self.needs_index();
        // A file in the index has its data, as Linux.
        let meta = !data && !indexed && self.fs.metacopy && kind == FileType::Regular;
        // A copy of the data needs the data, so a file without it fails before the change.
        let source = match kind {
            FileType::Regular if !meta => Some(self.data_inode()?),
            _ => None,
        };
        self.fs.set_impure(&dir)?;
        let upper = if indexed {
            let index = self.index_copy(&lower, source.as_ref())?;
            // The new link does not change the count of the links of the overlay file.
            let nlink = self.fs.union_nlink(&lower, &index, m.nlink);
            dir.link(&name, &index)?;
            self.fs.set_nlink(&index, nlink)?;
            self.indexed.store(true, Ordering::Release);
            index
        } else {
            let upper = self.copy_to(&dir, &name, &lower, meta, source.as_ref())?;
            // The upper inode shows the numbers of the lower inode, so another upper inode of
            // the same lower inode must not show them.
            let u = upper.metadata();
            self.fs.ino_of((m.dev, m.ino), (u.dev, u.ino));
            upper
        };
        self.metacopy.store(meta, Ordering::Release);
        *slot = Some(upper.clone());
        Ok(upper)
    }

    /// Gives the entry of the lower inode `lower` in the index directory, and makes it if it is
    /// not there, as `ovl_copy_up_tmpfile` of Linux with an index. A new entry is first a
    /// temporary file, which gets the data and the attributes, and then gets its name. Its
    /// attribute [`NLINK`] is the count of the links of the lower inode.
    fn index_copy(&self, lower: &InodeRef, source: Option<&InodeRef>) -> Result<InodeRef> {
        let fs = &self.fs;
        let dir = fs.index.as_ref().ok_or(Errno::EIO)?;
        let name = index_name(lower).ok_or(Errno::EIO)?;
        if let Some(index) = fs.lookup_index(lower, None)? {
            return Ok(index);
        }
        let kind = lower.metadata().file_type().ok_or(Errno::EIO)?;
        let temp = fs.temp_name();
        let index = self.copy_to(dir, &temp, lower, false, source)?;
        let done = fs
            .set_nlink(&index, lower.metadata().nlink)
            .and_then(|()| dir.rename(&temp, dir, &name));
        if let Err(e) = done {
            let _ = dir.unlink(&temp);
            return Err(e);
        }
        fs.indexed.fetch_add(1, Ordering::AcqRel);
        if index.metadata().file_type() != Some(kind) {
            return Err(Errno::EIO);
        }
        Ok(index)
    }

    /// Makes `name` in the upper directory `dir` as a copy of the lower inode `lower`, with its
    /// attributes and the attribute [`ORIGIN`], and gives it. A regular file gets the data of
    /// `source`, or only the size and the attribute [`METACOPY`] with `meta`.
    fn copy_to(
        &self,
        dir: &InodeRef,
        name: &[u8],
        lower: &InodeRef,
        meta: bool,
        source: Option<&InodeRef>,
    ) -> Result<InodeRef> {
        let m = lower.metadata();
        let perm = m.mode & mode::PERM_MASK;
        let kind = m.file_type().ok_or(Errno::EIO)?;
        let upper = match kind {
            FileType::Symlink => dir.symlink(name, &lower.read_link()?)?,
            FileType::Regular => {
                let file = dir.create(name, kind, perm, 0)?;
                match source {
                    Some(source) => copy_data(source, &file, m.size)?,
                    None => file.set_attr(&SetAttr { size: Some(m.size), ..SetAttr::default() })?,
                }
                file
            }
            _ => dir.create(name, kind, perm, m.rdev)?,
        };
        for attr in lower.list_xattr()? {
            // An upper layer without POSIX ACLs does not get the ACLs, as `ovl_copy_acl` of
            // Linux.
            if self.fs.is_private(&attr) || (acl::is_name(&attr) && !upper.posix_acl()) {
                continue;
            }
            if let Ok(value) = lower.get_xattr(&attr) {
                upper.set_xattr(&attr, &value, 0)?;
            }
        }
        if meta {
            upper.set_xattr(&self.fs.xattr(METACOPY), b"", 0)?;
        }
        self.fs.set_origin(&upper, lower)?;
        let mode = (kind != FileType::Symlink).then_some(perm);
        upper.set_attr(&SetAttr {
            mode,
            uid: Some(m.uid),
            gid: Some(m.gid),
            size: None,
            atime: Some(m.atime),
            mtime: Some(m.mtime),
            explicit_times: true,
        })?;
        self.copy_flags(lower, &upper)?;
        Ok(upper)
    }

    /// Prepares a change of the count of the links of the file, as `ovl_nlink_start` of Linux.
    /// A lower hard link that needs the index gets a copy up first, so the index keeps the
    /// count. The count goes to the attribute [`NLINK`] of the upper inode in the index, which
    /// this gives.
    fn nlink_start(&self) -> Result<Option<InodeRef>> {
        if self.fs.index.is_none() || self.is_dir() {
            return Ok(None);
        }
        if self.upper().is_none() && self.needs_index() {
            self.copy_up()?;
        }
        if !self.indexed.load(Ordering::Acquire) {
            return Ok(None);
        }
        let Some(upper) = self.upper() else { return Ok(None) };
        self.fs.set_nlink(&upper, self.metadata().nlink)?;
        Ok(Some(upper))
    }

    /// Ends a removal of a name of the file with the upper inode `index` in the index, as
    /// `ovl_nlink_end` and `ovl_cleanup_index` of Linux. After the removal of the last name,
    /// the entry in the index directory goes away. If the upper inode still has other links,
    /// the count of the links becomes the count of these links.
    fn nlink_end(&self, index: &InodeRef) {
        let fs = &self.fs;
        let (Some(lower), Some(dir)) = (self.top(), &fs.index) else { return };
        if fs.nlink_value(lower, index).is_none_or(|n| n > 0) {
            return;
        }
        let links = index.metadata().nlink;
        if links != 1 {
            let _ = fs.set_nlink(index, links - 1);
            return;
        }
        let Some(name) = index_name(lower) else { return };
        if dir.lookup(&name).is_ok_and(|entry| same_inode(&entry, index))
            && dir.unlink(&name).is_ok()
        {
            fs.indexed.fetch_add(1, Ordering::AcqRel);
        }
    }

    /// Gives the lower inode with the data of a regular file before a copy up.
    fn data_inode(&self) -> Result<InodeRef> {
        if self.is_metacopy() {
            return self.lowerdata.clone().ok_or(Errno::ENOENT);
        }
        self.top().cloned().ok_or(Errno::ENOENT)
    }

    /// Copies the data of a metacopy file to its upper inode `upper`, and removes the attribute
    /// [`METACOPY`], as `ovl_copy_up_meta_inode_data` of Linux.
    fn copy_data_up(&self, upper: &InodeRef) -> Result<()> {
        let _slot = self.upper.lock();
        if !self.is_metacopy() {
            return Ok(());
        }
        let source = self.lowerdata.clone().ok_or(Errno::ENOENT)?;
        copy_data(&source, upper, upper.metadata().size)?;
        match upper.remove_xattr(&self.fs.xattr(METACOPY)) {
            Ok(()) | Err(Errno::ENODATA) => {}
            Err(e) => return Err(e),
        }
        self.metacopy.store(false, Ordering::Release);
        Ok(())
    }

    /// Gives the inode flags of `lower` to the new upper inode `upper`, as `ovl_copy_fileattr` of
    /// Linux. The upper inode gets the flags of [`COPY_FLAGS`]. The attribute [`PROTATTR`] keeps
    /// the flags of [`PROT_FLAGS`].
    fn copy_flags(&self, lower: &InodeRef, upper: &InodeRef) -> Result<()> {
        // A file system without inode flags has nothing to copy.
        let Ok(flags) = lower.attr_flags() else { return Ok(()) };
        if flags & PROT_FLAGS != 0 {
            self.fs.set_prot_flags(upper, flags)?;
        }
        if flags & COPY_FLAGS == 0 {
            return Ok(());
        }
        let real = upper.attr_flags().unwrap_or(0);
        match upper.set_attr_flags((real & !COPY_FLAGS) | (flags & COPY_FLAGS)) {
            Ok(()) | Err(Errno::EOPNOTSUPP | Errno::ENOTTY) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Sets the attribute [`REDIRECT`] of the upper inode `upper` of this node before a rename,
    /// as `ovl_set_redirect` of Linux. A rename in the same directory keeps the old redirect,
    /// or gets the old name. A rename to another directory and a hard link of a lower hard link
    /// get an absolute path. An error gives `EXDEV`, so `mv` copies the files.
    fn set_redirect(&self, upper: &InodeRef, samedir: bool) -> Result<()> {
        let old = self.redirect.lock().clone();
        if old.is_some_and(|r| samedir || r[0] == b'/') {
            return Ok(());
        }
        let link = !self.is_dir() && self.top().is_some_and(|l| l.metadata().nlink > 1);
        let value = if samedir && !link { self.place.lock().1.clone() } else { self.path()? };
        upper.set_xattr(&self.fs.xattr(REDIRECT), &value, 0).map_err(|_| Errno::EXDEV)?;
        *self.redirect.lock() = Some(value);
        Ok(())
    }

    /// Gives the path of the node from the root for an absolute redirect, as `ovl_get_redirect`
    /// of Linux. The redirect of the node or of a parent replaces its name. An absolute
    /// redirect is the start of the path.
    fn path(&self) -> Result<Vec<u8>> {
        let mut parts = Vec::new();
        let mut node = self.arc()?;
        loop {
            let (parent, name) = node.place.lock().clone();
            let Some(parent) = parent else { break };
            let part = node.redirect.lock().clone().unwrap_or(name);
            let absolute = part.first() == Some(&b'/');
            parts.push(part);
            if absolute {
                break;
            }
            node = parent;
        }
        let mut out = Vec::new();
        for part in parts.iter().rev() {
            if part.first() != Some(&b'/') {
                out.push(b'/');
            }
            out.extend_from_slice(part);
        }
        Ok(out)
    }

    /// Gives the joined entries of the directory but `.` and `..`, in the order of the names.
    fn joined(&self) -> Result<Vec<DirEntry>> {
        // `None` is a name that a whiteout hides.
        let mut names: BTreeMap<Vec<u8>, Option<DirEntry>> = BTreeMap::new();
        let mut more = true;
        if let Some(dir) = self.upper() {
            for entry in real_entries(&dir)? {
                let hidden = self.fs.entry_is_whiteout(&dir, &entry);
                names.insert(entry.name.clone(), (!hidden).then_some(entry));
            }
            more = !self.fs.is_opaque(&dir);
        }
        if more {
            for (_, dir) in &self.lowers {
                for entry in real_entries(dir)? {
                    if names.contains_key(&entry.name) {
                        continue;
                    }
                    let hidden = self.fs.entry_is_whiteout(dir, &entry);
                    names.insert(entry.name.clone(), (!hidden).then_some(entry));
                }
            }
        }
        Ok(names.into_values().flatten().collect())
    }

    /// Removes the whiteouts of the upper directory `dir` before a removal of the directory.
    fn remove_whiteouts(&self, dir: &InodeRef) -> Result<()> {
        for entry in real_entries(dir)? {
            if self.fs.entry_is_whiteout(dir, &entry) {
                dir.unlink(&entry.name)?;
            }
        }
        Ok(())
    }

    /// Prepares the upper directory for a new name: copies the directory up and removes a
    /// whiteout of the name. Gives the upper directory and tells if it removed a whiteout.
    fn prepare_new(&self, name: &[u8]) -> Result<(InodeRef, bool)> {
        self.check_writable()?;
        let dir = self.copy_up()?;
        let whiteout = match dir.lookup(name) {
            Ok(i) if is_whiteout(&i) => {
                dir.unlink(name)?;
                true
            }
            _ => false,
        };
        Ok((dir, whiteout))
    }

    /// Adds a node for the new upper inode `inode` of `name`.
    fn added(&self, name: &[u8], inode: InodeRef) -> Result<InodeRef> {
        let parent = Some(self.arc()?);
        let found = Found { upper: Some(inode), ..Found::default() };
        let node = Node::new(&self.fs, parent, name.to_vec(), found).ok_or(Errno::EIO)?;
        self.forget(name);
        self.children.lock().insert(name.to_vec(), Arc::downgrade(&node));
        Ok(node)
    }

    /// Makes a whiteout of `name` in the upper directory `dir` if a lower directory shows the
    /// name.
    fn white_out(&self, dir: &InodeRef, name: &[u8]) -> Result<()> {
        if self.lower_has(name) {
            self.fs.make_whiteout(dir, name)?;
        }
        Ok(())
    }

    /// Checks that the directory node `node` has no entries in the joined view.
    fn check_empty(node: &Node) -> Result<()> {
        if node.joined()?.is_empty() { Ok(()) } else { Err(Errno::ENOTEMPTY) }
    }
}

impl Drop for Node {
    /// Keeps the node in its directory as an unused node, if the directory still gives the node
    /// for its name, as `dput` of Linux keeps a dentry on the LRU list.
    fn drop(&mut self) {
        let (parent, name) = core::mem::take(&mut *self.place.lock());
        let Some(parent) = parent else { return };
        {
            let mut children = parent.children.lock();
            if !children.get(&name).is_some_and(|w| w.ptr_eq(&self.this)) {
                return;
            }
            children.remove(&name);
            let saved = Saved {
                upper: self.upper.lock().take(),
                first: self.first.clone(),
                from_upper: self.from_upper,
                lowers: core::mem::take(&mut self.lowers),
                redirect: self.redirect.lock().take(),
                metacopy: self.metacopy.load(Ordering::Relaxed),
                lowerdata: self.lowerdata.take(),
                indexed: self.indexed.load(Ordering::Relaxed),
                unused: core::mem::take(&mut *self.unused.lock()),
                stamp: self.fs.cache.next.fetch_add(1, Ordering::Relaxed),
                _count: Counted::new(&self.fs),
            };
            // The lock on `children` stops a new node of the name until the node is kept.
            parent.keep(name, saved);
        }
        self.fs.cache.shrink(UNUSED_MAX);
    }
}

/// An entry of the LRU list: the directory, the name and the stamp of an unused node.
type LruEntry = (Weak<Node>, Vec<u8>, u64);

/// The unused nodes of a mount in the order of their use, as the LRU list of dentries of Linux.
struct Cache {
    /// The directory, the name and the stamp of each unused node, the oldest first. An entry
    /// whose node is not unused now is out of date, and the eviction skips it.
    lru: SpinLock<VecDeque<LruEntry>>,
    /// The count of the unused nodes of the mount, with the unused nodes in unused directories.
    count: AtomicUsize,
    /// The stamp of the next unused node.
    next: AtomicU64,
}

impl Default for Cache {
    fn default() -> Self {
        Cache {
            lru: SpinLock::new(VecDeque::new()),
            count: AtomicUsize::new(0),
            next: AtomicU64::new(0),
        }
    }
}

impl Cache {
    /// Evicts the oldest unused nodes until the mount has `max` of them at most. An evicted
    /// directory takes its unused children with it.
    fn shrink(&self, max: usize) {
        while self.count.load(Ordering::Relaxed) > max {
            let Some((dir, name, stamp)) = self.lru.lock().pop_front() else { break };
            let Some(dir) = dir.upgrade() else { continue };
            let victim = {
                let mut unused = dir.unused.lock();
                match unused.get(&name) {
                    Some(s) if s.stamp == stamp => unused.remove(&name),
                    _ => None,
                }
            };
            drop(victim);
        }
        // Removes the entries that are out of date, so that the list does not grow. The check
        // is not under the lock, because the drop of a directory can add an entry.
        let old = {
            let mut lru = self.lru.lock();
            if lru.len() <= 2 * max.max(16) {
                return;
            }
            core::mem::take(&mut *lru)
        };
        let mut valid: VecDeque<_> = old
            .into_iter()
            .filter(|(dir, name, stamp)| {
                dir.upgrade()
                    .is_some_and(|d| d.unused.lock().get(name).is_some_and(|s| s.stamp == *stamp))
            })
            .collect();
        let mut lru = self.lru.lock();
        valid.append(&mut lru);
        *lru = valid;
    }
}

/// A node that is not in use: the inodes of its layers, the state that the lookup and the
/// changes gave to it, and its unused children.
struct Saved {
    upper: Option<InodeRef>,
    first: InodeRef,
    from_upper: bool,
    lowers: Vec<(usize, InodeRef)>,
    redirect: Option<Vec<u8>>,
    metacopy: bool,
    lowerdata: Option<InodeRef>,
    indexed: bool,
    unused: BTreeMap<Vec<u8>, Saved>,
    /// The order of the node in the LRU list of the mount.
    stamp: u64,
    _count: Counted,
}

/// One unused node in the count of the mount.
struct Counted(Arc<Fs>);

impl Counted {
    fn new(fs: &Arc<Fs>) -> Self {
        fs.cache.count.fetch_add(1, Ordering::Relaxed);
        Counted(fs.clone())
    }
}

impl Drop for Counted {
    fn drop(&mut self) {
        self.0.cache.count.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Copies `size` bytes of the regular file `from` to `to`.
fn copy_data(from: &InodeRef, to: &InodeRef, size: u64) -> Result<()> {
    let mut buf = vec![0u8; CHUNK];
    let mut pos = 0u64;
    while pos < size {
        let n = from.read_at(pos, &mut buf)?;
        if n == 0 {
            break;
        }
        let mut done = 0;
        while done < n {
            done += to.write_at(pos + done as u64, &buf[done..n])?;
        }
        pos += n as u64;
    }
    Ok(())
}

impl Inode for Node {
    fn metadata(&self) -> Metadata {
        let mut m = self.real().metadata();
        // A metacopy file has the blocks of its data. A file without its data gets the blocks
        // from its size, as Linux.
        if self.is_metacopy() {
            m.blocks = match &self.lowerdata {
                Some(data) => data.metadata().blocks,
                None => {
                    let block = u64::from(m.blksize).max(512);
                    (m.size.div_ceil(block) * block) >> 9
                }
            };
        }
        // A file in the index has the count of the links of the overlay file, as Linux.
        if let (Some(index), Some(lower)) = (self.index_upper(), self.top()) {
            m.nlink = self.fs.union_nlink(lower, &index, m.nlink);
        }
        // A directory joins layers, so it has the device of the mount. Another file shows the
        // device of its layer, as Linux without the `xino` feature.
        let (dev, ino) = self.identity();
        m.dev = if m.is_dir() { self.fs.dev } else { dev };
        m.ino = ino;
        m
    }

    fn set_attr(&self, attr: &SetAttr) -> Result<()> {
        self.check_writable()?;
        // A change of the size needs the data.
        self.copy_up_with(attr.size.is_some())?.set_attr(attr)
    }

    fn set_atime(&self, time: Timespec) -> Result<()> {
        // An access does not copy a file up.
        match self.upper() {
            Some(upper) => upper.set_atime(time),
            None => Ok(()),
        }
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        self.data()?.read_at(offset, buf)
    }

    fn write_at(&self, offset: u64, buf: &[u8]) -> Result<usize> {
        self.check_writable()?;
        self.copy_up_with(true)?.write_at(offset, buf)
    }

    fn fiemap(&self, start: u64, len: u64) -> Result<Vec<rk_vfs::inode::FiemapExtent>> {
        self.data()?.fiemap(start, len)
    }

    fn fiemap_xattr(&self) -> Result<Option<rk_vfs::inode::FiemapExtent>> {
        self.real().fiemap_xattr()
    }

    fn attr_flags(&self) -> Result<u32> {
        match self.upper() {
            // The upper inode keeps the immutable and append-only flags in an attribute.
            Some(upper) => {
                let prot = self.fs.prot_flags(&upper);
                Ok(upper.attr_flags().unwrap_or(0) & !PROT_FLAGS | prot)
            }
            None => self.first.attr_flags(),
        }
    }

    fn set_attr_flags(&self, flags: u32) -> Result<()> {
        self.check_writable()?;
        let upper = self.copy_up()?;
        self.fs.set_prot_flags(&upper, flags)?;
        upper.set_attr_flags(flags & !PROT_FLAGS)
    }

    fn fallocate(&self, mode: u32, offset: u64, len: u64) -> Result<()> {
        self.check_writable()?;
        self.copy_up_with(true)?.fallocate(mode, offset, len)
    }

    fn sync(&self) -> Result<()> {
        match self.upper() {
            Some(upper) => upper.sync(),
            None => Ok(()),
        }
    }

    fn lookup(&self, name: &[u8]) -> Result<InodeRef> {
        if !self.is_dir() {
            return Err(Errno::ENOTDIR);
        }
        Ok(self.child(name)?)
    }

    fn create(&self, name: &[u8], kind: FileType, perm: u32, rdev: u64) -> Result<InodeRef> {
        let (dir, whiteout) = self.prepare_new(name)?;
        let inode = dir.create(name, kind, perm, rdev)?;
        // A new directory over a removed directory must not show the old entries. With a
        // feature that needs fixed lower layers, a new directory in a merged directory is
        // opaque too, as `ovl_create_upper` of Linux.
        let merged = self.fs.strict() && !self.lowers.is_empty();
        if kind == FileType::Directory && (whiteout || merged || self.lower_has(name)) {
            inode.set_xattr(&self.fs.xattr(OPAQUE), b"y", 0)?;
        }
        self.added(name, inode)
    }

    fn symlink(&self, name: &[u8], target: &[u8]) -> Result<InodeRef> {
        let (dir, _) = self.prepare_new(name)?;
        let inode = dir.symlink(name, target)?;
        self.added(name, inode)
    }

    fn link(&self, name: &[u8], inode: &InodeRef) -> Result<()> {
        let node = self.same_fs(inode)?;
        self.check_writable()?;
        let target = node.copy_up()?;
        // The lookup of the new name finds the data of a metacopy file through an absolute
        // redirect, as `ovl_set_link_redirect` of Linux.
        if node.is_metacopy() {
            node.set_redirect(&target, false)?;
        }
        node.nlink_start()?;
        let (dir, _) = self.prepare_new(name)?;
        dir.link(name, &target)
    }

    fn unlink(&self, name: &[u8]) -> Result<()> {
        self.check_writable()?;
        let node = self.child(name)?;
        if node.is_dir() {
            return Err(Errno::EISDIR);
        }
        let dir = self.copy_up()?;
        let index = node.nlink_start()?;
        Node::check_upper(&dir, name, &node)?;
        if node.upper().is_some() {
            dir.unlink(name)?;
        }
        self.white_out(&dir, name)?;
        if let Some(index) = index {
            node.nlink_end(&index);
        }
        self.forget(name);
        Ok(())
    }

    fn rmdir(&self, name: &[u8]) -> Result<()> {
        self.check_writable()?;
        let node = self.child(name)?;
        if !node.is_dir() {
            return Err(Errno::ENOTDIR);
        }
        Node::check_empty(&node)?;
        let dir = self.copy_up()?;
        Node::check_upper(&dir, name, &node)?;
        if let Some(upper) = node.upper() {
            self.remove_whiteouts(&upper)?;
            dir.rmdir(name)?;
        }
        self.white_out(&dir, name)?;
        self.forget(name);
        Ok(())
    }

    fn rename(&self, old: &[u8], new_dir: &InodeRef, new: &[u8]) -> Result<()> {
        let to = self.same_fs(new_dir)?;
        self.check_writable()?;
        let node = self.child(old)?;
        let moving_dir = node.is_dir();
        // A directory with lower directories moves only with a redirect.
        let merged = moving_dir && !node.lowers.is_empty();
        if merged && self.fs.redirect != Redirect::On {
            return Err(Errno::EXDEV);
        }
        let src = node.copy_up()?;
        let from_dir = self.copy_up()?;
        let to_dir = to.copy_up()?;
        // The file that the rename replaces, with its upper inode in the index.
        let mut replaced = None;
        match to.child(new) {
            Ok(target) if target.is_dir() => {
                Node::check_empty(&target)?;
                if let Some(upper) = target.upper() {
                    self.remove_whiteouts(&upper)?;
                }
            }
            Ok(target) if !Arc::ptr_eq(&target, &node) => {
                replaced = target.nlink_start()?.map(|index| (target, index));
            }
            Ok(_) | Err(Errno::ENOENT) => {}
            Err(e) => return Err(e),
        }
        if let Ok(i) = to_dir.lookup(new)
            && is_whiteout(&i)
        {
            to_dir.unlink(new)?;
        }
        let samedir = Arc::ptr_eq(&to, &self.arc()?);
        // The lookup of the new name finds the lower inodes of a merged directory or the data
        // of a metacopy file through a redirect.
        if merged || (!moving_dir && node.is_metacopy()) {
            node.set_redirect(&src, samedir)?;
        }
        from_dir.rename(old, &to_dir, new)?;
        if moving_dir && !merged && to.lower_has(new) {
            src.set_xattr(&self.fs.xattr(OPAQUE), b"y", 0)?;
        }
        // The new directory can now have a name with the inode number of a lower inode.
        if !samedir && !node.lowers.is_empty() {
            self.fs.set_impure(&to_dir)?;
        }
        self.white_out(&from_dir, old)?;
        if let Some((target, index)) = replaced {
            target.nlink_end(&index);
        }
        self.forget(old);
        to.forget(new);
        *node.place.lock() = (Some(to.clone()), new.to_vec());
        to.children.lock().insert(new.to_vec(), Arc::downgrade(&node));
        Ok(())
    }

    fn read_link(&self) -> Result<Vec<u8>> {
        self.real().read_link()
    }

    fn read_dir(&self, pos: u64) -> Result<Option<(DirEntry, u64)>> {
        if !self.is_dir() {
            return Err(Errno::ENOTDIR);
        }
        let mut entries = self.entries.lock();
        if pos == 0 {
            let ino = self.metadata().ino;
            let parent = self.place.lock().0.clone();
            let up = parent.map_or(ino, |p| p.metadata().ino);
            let mut list = vec![
                DirEntry { ino, kind: FileType::Directory, name: b".".to_vec() },
                DirEntry { ino: up, kind: FileType::Directory, name: b"..".to_vec() },
            ];
            let mut joined = self.joined()?;
            // A merged or impure directory can have names with the inode numbers of lower
            // inodes, so the entries get the numbers of `stat`, as `ovl_cache_update_ino` of
            // Linux.
            let impure = self.upper().is_some_and(|u| {
                !self.lowers.is_empty() || u.get_xattr(&self.fs.xattr(IMPURE)).is_ok()
            });
            if impure {
                // Tells if a name has the inode number of a lower inode.
                let mut moved = false;
                for entry in &mut joined {
                    if let Ok(node) = self.child(&entry.name) {
                        let ino = node.metadata().ino;
                        moved |= ino != entry.ino;
                        entry.ino = ino;
                    }
                }
                // An upper directory without lower directories and without such names is pure
                // again, so it loses the attribute, as `ovl_dir_read_impure` of Linux.
                if !moved
                    && self.lowers.is_empty()
                    && !self.is_read_only()
                    && let Some(upper) = self.upper()
                {
                    let _ = upper.remove_xattr(&self.fs.xattr(IMPURE));
                }
            }
            list.extend(joined);
            *entries = list;
        }
        let index = usize::try_from(pos).unwrap_or(usize::MAX);
        Ok(entries.get(index).map(|e| (e.clone(), pos + 1)))
    }

    /// The ACLs come from the real inode. A layer without POSIX ACLs has none, as `ovl_get_acl`
    /// of Linux.
    fn get_xattr(&self, name: &[u8]) -> Result<Vec<u8>> {
        let real = self.real();
        if acl::is_name(name) && !real.posix_acl() {
            return Err(Errno::ENODATA);
        }
        real.get_xattr(&self.fs.escape(name))
    }

    fn set_xattr(&self, name: &[u8], value: &[u8], flags: u32) -> Result<()> {
        self.check_writable()?;
        self.check_acl(name)?;
        let name = self.fs.escape(name);
        self.copy_up()?.set_xattr(&name, value, flags)
    }

    fn list_xattr(&self) -> Result<Vec<Vec<u8>>> {
        let real = self.real();
        let names = real.list_xattr()?;
        let shown = |n: &&Vec<u8>| acl::listed(&*real, n);
        Ok(names.iter().filter(shown).filter_map(|n| self.fs.unescape(n)).collect())
    }

    fn remove_xattr(&self, name: &[u8]) -> Result<()> {
        self.check_writable()?;
        self.check_acl(name)?;
        let name = self.fs.escape(name);
        self.real().get_xattr(&name)?;
        self.copy_up()?.remove_xattr(&name)
    }

    fn fs_id(&self) -> u64 {
        self.fs.dev
    }

    fn fs_fsid(&self) -> u64 {
        self.fs.fsid
    }

    fn fs_stat(&self) -> Option<FsStat> {
        let mut root = self.arc().ok()?;
        loop {
            let parent = root.place.lock().0.clone();
            match parent {
                Some(p) => root = p,
                None => break,
            }
        }
        root.real().fs_stat()
    }

    fn fs_magic(&self) -> u64 {
        OVERLAYFS_SUPER_MAGIC
    }

    fn set_read_only(&self, read_only: bool) -> Result<()> {
        // A mount without an upper directory or without a work directory stays read only, as
        // `ovl_reconfigure` of Linux.
        if !read_only && !self.fs.writable {
            return Err(Errno::EROFS);
        }
        self.fs.read_only.store(read_only, Ordering::Relaxed);
        Ok(())
    }

    fn is_read_only(&self) -> bool {
        self.fs.read_only.load(Ordering::Relaxed)
    }

    /// overlayfs has POSIX ACLs, as Linux. The ACLs are the ACLs of the layers.
    fn posix_acl(&self) -> bool {
        true
    }

    fn fs_options(&self) -> Vec<u8> {
        self.fs.options.clone()
    }
}

#[cfg(test)]
mod tests;
