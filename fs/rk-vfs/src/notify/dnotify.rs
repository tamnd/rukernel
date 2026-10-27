//! dnotify: a signal for each change in a directory, as fs/notify/dnotify/dnotify.c of Linux.
//!
//! `fcntl(F_NOTIFY)` adds an entry for an open directory. All the entries of a directory share one
//! mark of the dnotify group on the inode, and the mark has the events of all the entries. An
//! event sends the signal of the open file to the owner of the file. The entry then goes away,
//! unless it has `DN_MULTISHOT`. The close of the descriptor removes the entry of the descriptor.

use super::{Group, Mark, add_mark, destroy_mark, mask};
use crate::file::File;
use crate::inode::{InodeRef, Result};
use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_abi::native::dnotify::{
    DN_ACCESS, DN_ATTRIB, DN_CREATE, DN_DELETE, DN_MODIFY, DN_MULTISHOT, DN_RENAME,
};
use rk_frame::sync::{Once, SpinLock};

/// One `F_NOTIFY` request, as `struct dnotify_struct` of Linux.
struct Entry {
    /// The descriptor table of the request.
    owner: usize,
    file: Weak<File>,
    fd: i32,
    /// The events, in the bits of the marks.
    mask: u32,
}

/// The mark of a directory and its entries, as `struct dnotify_mark` of Linux.
struct Dir {
    mark: Arc<Mark>,
    entries: Vec<Entry>,
}

/// The dnotify group. There is one, as `dnotify_group` of Linux.
struct Dnotify {
    /// The directories with entries, by the address of the inode.
    dirs: SpinLock<BTreeMap<usize, Dir>>,
}

static GROUP: Once<Arc<Dnotify>> = Once::new();

/// The function that sends the signal of a file to its owner.
static SIGIO: Once<fn(&File, i32)> = Once::new();

/// Gives the VFS the function that sends the signal of the open file to its owner, with the
/// descriptor, as `send_sigio` of Linux with `POLL_MSG`. Only the first call has an effect.
pub fn set_sigio(f: fn(&File, i32)) {
    SIGIO.call_once(|| f);
}

fn group() -> &'static Arc<Dnotify> {
    GROUP.call_once(|| Arc::new(Dnotify { dirs: SpinLock::new(BTreeMap::new()) }))
}

fn key(inode: &InodeRef) -> usize {
    Arc::as_ptr(inode).cast::<()>() as usize
}

/// The events of the marks for the `DN_*` bits of `arg`, as `convert_arg` of Linux.
fn convert(arg: u32) -> u32 {
    let mut m = mask::EVENT_ON_CHILD;
    if arg & DN_MULTISHOT != 0 {
        m |= mask::DN_MULTISHOT;
    }
    if arg & DN_DELETE != 0 {
        m |= mask::DELETE | mask::MOVED_FROM;
    }
    if arg & DN_MODIFY != 0 {
        m |= mask::MODIFY;
    }
    if arg & DN_ACCESS != 0 {
        m |= mask::ACCESS;
    }
    if arg & DN_ATTRIB != 0 {
        m |= mask::ATTRIB;
    }
    if arg & DN_RENAME != 0 {
        m |= mask::RENAME;
    }
    if arg & DN_CREATE != 0 {
        m |= mask::CREATE | mask::MOVED_TO;
    }
    m
}

/// Sets the events of the mark of `dir` to those of its entries, as
/// `dnotify_recalc_inode_mask` of Linux.
fn recalc(dir: &Dir) {
    let m = dir.entries.iter().fold(0, |m, e| m | (e.mask & !mask::DN_MULTISHOT));
    dir.mark.set_mask(m | mask::EVENT_ON_CHILD);
}

/// `fcntl(fd, F_NOTIFY, arg)` for the open file `file`, as `fcntl_dirnotify` of Linux. `owner`
/// is the descriptor table of the call, and `tgid` is the process that becomes the owner of the
/// file. An `arg` without events removes the entry of the descriptor.
///
/// # Errors
///
/// Gives `ENOTDIR` if the file is not a directory.
pub fn fcntl(file: &Arc<File>, fd: i32, owner: usize, arg: u32, tgid: i32) -> Result<()> {
    if arg & !DN_MULTISHOT == 0 {
        flush(file, owner);
        return Ok(());
    }
    let inode = file.inode().ok_or(Errno::ENOTDIR)?;
    if !inode.metadata().is_dir() {
        return Err(Errno::ENOTDIR);
    }
    let m = convert(arg);
    let g = group();
    let mut dirs = g.dirs.lock();
    let dir = dirs.entry(key(inode)).or_insert_with(|| Dir {
        mark: add_mark(g.clone(), inode, mask::EVENT_ON_CHILD, 0),
        entries: Vec::new(),
    });
    file.set_owner(tgid);
    let same = |e: &&mut Entry| e.owner == owner && core::ptr::eq(e.file.as_ptr(), &**file);
    match dir.entries.iter_mut().find(same) {
        Some(e) => {
            e.fd = fd;
            e.mask |= m;
        }
        None => dir.entries.push(Entry { owner, file: Arc::downgrade(file), fd, mask: m }),
    }
    recalc(dir);
    Ok(())
}

/// Removes the entry of the descriptor table `owner` for `file`, because the table closed a
/// descriptor of the file, as `dnotify_flush` of Linux. The mark goes away with its last entry.
pub fn flush(file: &File, owner: usize) {
    let Some(g) = GROUP.get() else { return };
    let Some(inode) = file.inode() else { return };
    let gone = {
        let mut dirs = g.dirs.lock();
        let k = key(inode);
        let Some(dir) = dirs.get_mut(&k) else { return };
        let Some(i) = dir
            .entries
            .iter()
            .position(|e| e.owner == owner && core::ptr::eq(e.file.as_ptr(), file))
        else {
            return;
        };
        dir.entries.remove(i);
        recalc(dir);
        if !dir.entries.is_empty() {
            return;
        }
        dirs.remove(&k).map(|d| d.mark)
    };
    if let Some(mark) = gone {
        destroy_mark(&mark);
    }
}

impl Group for Dnotify {
    fn handle_event(&self, mark: &Arc<Mark>, m: u32, name: Option<&[u8]>, _cookie: u32) {
        // An event of a file that is not a directory and not a child of the directory.
        if name.is_none() && m & mask::ISDIR == 0 {
            return;
        }
        let Some(inode) = mark.inode() else { return };
        let test = m & !mask::EVENT_ON_CHILD;
        let mut send = Vec::new();
        {
            let mut dirs = self.dirs.lock();
            let Some(dir) = dirs.get_mut(&key(inode)) else { return };
            dir.entries.retain(|e| {
                if e.mask & test == 0 {
                    return true;
                }
                send.push((e.file.clone(), e.fd));
                e.mask & mask::DN_MULTISHOT != 0
            });
            recalc(dir);
        }
        let Some(sigio) = SIGIO.get() else { return };
        for (file, fd) in send {
            if let Some(file) = file.upgrade() {
                sigio(&file, fd);
            }
        }
    }

    fn freeing_mark(&self, mark: &Arc<Mark>) {
        self.dirs.lock().retain(|_, d| !Arc::ptr_eq(&d.mark, mark));
    }
}
