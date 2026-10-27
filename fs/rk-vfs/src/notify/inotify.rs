//! inotify, as fs/notify/inotify/inotify_user.c and inotify_fsnotify.c of Linux.
//!
//! An inotify instance is a group of marks. Each mark is a watch with a watch descriptor. The
//! events of the marks go to the queue of the instance, and a read of the file of the instance
//! takes them as `struct inotify_event` records.
//!
//! The constants are the values of include/uapi/linux/inotify.h. The generated ABI crate has no
//! group for them yet.

use super::queue::{Added, Event, Queue};
use super::{Group, Mark, add_mark, destroy_mark, mask};
use crate::file::{File, FileOps, UserMemory, events};
use crate::inode::{InodeRef, Result};
use crate::wait::{PollTable, WaitQueue};
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use rk_abi::Errno;
use rk_frame::sync::SpinLock;

/// The flags of `add_watch` that are not events, from include/uapi/linux/inotify.h.
pub mod flags {
    /// Only a directory, `IN_ONLYDIR`.
    pub const ONLYDIR: u32 = 0x0100_0000;
    /// Do not follow a symbolic link, `IN_DONT_FOLLOW`.
    pub const DONT_FOLLOW: u32 = 0x0200_0000;
    /// No events of children that have no name, `IN_EXCL_UNLINK`.
    pub const EXCL_UNLINK: u32 = 0x0400_0000;
    /// Add the events to the mask of the watch, `IN_MASK_CREATE`.
    pub const MASK_CREATE: u32 = 0x1000_0000;
    /// Add the events to the mask of the watch, `IN_MASK_ADD`.
    pub const MASK_ADD: u32 = 0x2000_0000;
    /// The watch goes after one event, `IN_ONESHOT`.
    pub const ONESHOT: u32 = 0x8000_0000;
    /// The flag of `inotify_init1` for close on exec, `IN_CLOEXEC`, which is `O_CLOEXEC`.
    pub const CLOEXEC: u32 = 0o2_000_000;
    /// The flag of `inotify_init1` for a file that does not block, `IN_NONBLOCK`.
    pub const NONBLOCK: u32 = 0o4000;
}

/// The bits of a mask that `add_watch` takes, `ALL_INOTIFY_BITS` of Linux.
pub const ALL_BITS: u32 = mask::ALL_EVENTS
    | mask::UNMOUNT
    | mask::Q_OVERFLOW
    | mask::IGNORED
    | flags::ONLYDIR
    | flags::DONT_FOLLOW
    | flags::EXCL_UNLINK
    | flags::MASK_ADD
    | flags::MASK_CREATE
    | mask::ISDIR
    | flags::ONESHOT;

/// The bits of a mask that the user gave and that the mark keeps, `INOTIFY_USER_MASK` of Linux.
const USER_MASK: u32 = mask::ALL_EVENTS | flags::ONESHOT | flags::EXCL_UNLINK;

/// `fs.inotify.max_user_instances`: the most instances of one user.
pub static MAX_USER_INSTANCES: AtomicU32 = AtomicU32::new(128);

/// `fs.inotify.max_user_watches`: the most watches of one user, the least default of Linux.
pub static MAX_USER_WATCHES: AtomicU32 = AtomicU32::new(8192);

/// `fs.inotify.max_queued_events`: the size of the queue of a new instance.
pub static MAX_QUEUED_EVENTS: AtomicU32 = AtomicU32::new(16384);

/// The instances and the watches of each user, as the ucounts of Linux.
static USERS: SpinLock<BTreeMap<u32, (u32, u32)>> = SpinLock::new(BTreeMap::new());

/// The highest watch descriptor, as `idr_alloc_cyclic` of Linux gives them.
const WD_MAX: i32 = i32::MAX;

struct State {
    queue: Queue,
    watches: BTreeMap<i32, Arc<Mark>>,
    /// The last watch descriptor.
    last_wd: i32,
    /// The file of the instance is closed, so the marks that go away queue nothing.
    closed: bool,
}

/// An inotify instance.
pub struct Inotify {
    me: Weak<Inotify>,
    state: SpinLock<State>,
    wait: Arc<WaitQueue>,
    events: AtomicU64,
    /// The user that the instance and its watches count for.
    uid: u32,
}

impl Inotify {
    fn wake(&self) {
        self.events.fetch_add(1, Ordering::Relaxed);
        self.wait.wake_all();
    }

    fn queue(&self, event: Event, merge: bool) {
        let added = {
            let mut st = self.state.lock();
            if st.closed {
                return;
            }
            st.queue.push(event, merge)
        };
        if matches!(added, Added::Queued | Added::Overflow) {
            self.wake();
        }
    }

    /// `inotify_add_watch` for the inode `inode`, after the walk and the checks of the mask.
    /// Gives the watch descriptor, as `inotify_update_watch` of Linux.
    ///
    /// # Errors
    ///
    /// Gives `EEXIST` for `IN_MASK_CREATE` and an inode that has a watch, and `ENOSPC` if the
    /// user has `max_user_watches` watches.
    pub fn add_watch(&self, inode: &InodeRef, arg: u32) -> Result<i32> {
        let mut new = mask::UNMOUNT | (arg & USER_MASK);
        if inode.metadata().is_dir() {
            new |= mask::EVENT_ON_CHILD;
        }
        let mut st = self.state.lock();
        if let Some(mark) =
            st.watches.values().find(|m| m.inode().is_some_and(|i| Arc::ptr_eq(i, inode)))
        {
            if arg & flags::MASK_CREATE != 0 {
                return Err(Errno::EEXIST);
            }
            if arg & flags::MASK_ADD != 0 {
                new |= mark.mask();
            }
            mark.set_mask(new);
            return Ok(mark.id());
        }
        let group: Arc<dyn Group> = self.me.upgrade().ok_or(Errno::EBADF)?;
        {
            let mut users = USERS.lock();
            let count = users.entry(self.uid).or_insert((0, 0));
            if count.1 >= MAX_USER_WATCHES.load(Ordering::Relaxed) {
                return Err(Errno::ENOSPC);
            }
            count.1 += 1;
        }
        let mut wd = st.last_wd;
        loop {
            wd = if wd == WD_MAX { 1 } else { wd + 1 };
            if !st.watches.contains_key(&wd) {
                break;
            }
        }
        st.last_wd = wd;
        let mark = add_mark(group, inode, new, wd);
        st.watches.insert(wd, mark);
        Ok(wd)
    }

    /// `inotify_rm_watch`: the watch goes and the queue gets `IN_IGNORED`.
    ///
    /// # Errors
    ///
    /// Gives `EINVAL` if there is no watch `wd`.
    pub fn rm_watch(&self, wd: i32) -> Result<()> {
        let mark = self.state.lock().watches.get(&wd).cloned().ok_or(Errno::EINVAL)?;
        destroy_mark(&mark);
        Ok(())
    }

    /// The lines of `/proc/PID/fdinfo` for the watches, as `inotify_show_fdinfo` of Linux.
    pub fn fdinfo(&self) -> Vec<u8> {
        let marks: Vec<Arc<Mark>> = self.state.lock().watches.values().cloned().collect();
        let mut out = Vec::new();
        for mark in marks {
            let Some(inode) = mark.inode() else { continue };
            let meta = inode.metadata();
            out.extend_from_slice(
                format!(
                    "inotify wd:{:x} ino:{:x} sdev:{:x} mask:{:x} ignored_mask:0\n",
                    mark.id(),
                    meta.ino,
                    kernel_dev(meta.dev),
                    mark.mask() & USER_MASK,
                )
                .as_bytes(),
            );
        }
        out
    }

    /// Removes the watches when the file of the instance closes, as `inotify_release` of Linux.
    fn release(&self) {
        let marks: Vec<Arc<Mark>> = {
            let mut st = self.state.lock();
            st.closed = true;
            st.queue.clear();
            st.watches.values().cloned().collect()
        };
        for mark in marks {
            destroy_mark(&mark);
        }
        let mut users = USERS.lock();
        if let Some(count) = users.get_mut(&self.uid) {
            count.0 = count.0.saturating_sub(1);
            if *count == (0, 0) {
                users.remove(&self.uid);
            }
        }
    }
}

/// The device number in the encoding of the kernel, `MKDEV`, from the encoding of `stat`.
fn kernel_dev(dev: u64) -> u64 {
    let major = ((dev >> 8) & 0xfff) | ((dev >> 32) & !0xfff);
    let minor = (dev & 0xff) | ((dev >> 12) & !0xff);
    (major << 20) | minor
}

impl Group for Inotify {
    fn handle_event(&self, mark: &Arc<Mark>, mask: u32, name: Option<&[u8]>, cookie: u32) {
        if !mark.alive() {
            return;
        }
        let mut m = mask;
        // As `inotify_handle_inode_event` of Linux: inotify never gave `IN_ISDIR` with these.
        if m & (mask::MOVE_SELF | mask::DELETE_SELF) != 0 {
            m &= !mask::ISDIR;
        }
        m &= mask::ALL_EVENTS | mask::ISDIR | mask::UNMOUNT;
        let event = Event { wd: mark.id(), mask: m, cookie, name: name.unwrap_or(b"").to_vec() };
        self.queue(event, true);
        if mark.mask() & flags::ONESHOT != 0 {
            destroy_mark(mark);
        }
    }

    fn freeing_mark(&self, mark: &Arc<Mark>) {
        {
            let mut st = self.state.lock();
            if st.watches.get(&mark.id()).is_some_and(|m| Arc::ptr_eq(m, mark)) {
                st.watches.remove(&mark.id());
            }
        }
        {
            let mut users = USERS.lock();
            if let Some(count) = users.get_mut(&self.uid) {
                count.1 = count.1.saturating_sub(1);
            }
        }
        let event = Event { wd: mark.id(), mask: mask::IGNORED, cookie: 0, name: Vec::new() };
        self.queue(event, false);
    }
}

/// The operations of the file of an inotify instance.
pub struct InotifyFile {
    group: Arc<Inotify>,
}

impl InotifyFile {
    /// Makes a new instance for the user `uid`, as `inotify_new_group` of Linux.
    ///
    /// # Errors
    ///
    /// Gives `EMFILE` if the user has `max_user_instances` instances.
    pub fn new(uid: u32) -> Result<Self> {
        {
            let mut users = USERS.lock();
            let count = users.entry(uid).or_insert((0, 0));
            if count.0 >= MAX_USER_INSTANCES.load(Ordering::Relaxed) {
                return Err(Errno::EMFILE);
            }
            count.0 += 1;
        }
        let max = MAX_QUEUED_EVENTS.load(Ordering::Relaxed) as usize;
        let group = Arc::new_cyclic(|me| Inotify {
            me: me.clone(),
            state: SpinLock::new(State {
                queue: Queue::new(max),
                watches: BTreeMap::new(),
                last_wd: 0,
                closed: false,
            }),
            wait: Arc::new(WaitQueue::new()),
            events: AtomicU64::new(0),
            uid,
        });
        Ok(Self { group })
    }

    /// The instance.
    pub fn group(&self) -> &Arc<Inotify> {
        &self.group
    }
}

impl Drop for InotifyFile {
    fn drop(&mut self) {
        self.group.release();
    }
}

/// `FIONREAD` of `asm/ioctls.h`.
const FIONREAD: u32 = rk_abi::native::ioctls::FIONREAD;

impl FileOps for InotifyFile {
    /// A read takes whole events, as `inotify_read` of Linux.
    fn read(&self, file: &File, buf: &mut [u8]) -> Result<usize> {
        let nonblock = file.flags().nonblock();
        let g = &self.group;
        let out = g.wait.wait_interruptible(|| {
            let mut st = g.state.lock();
            let mut out = Vec::new();
            loop {
                match st.queue.pop(buf.len() - out.len()) {
                    Ok(Some(event)) => event.encode(&mut out),
                    Ok(None) => break,
                    Err(()) if out.is_empty() => return Err(Errno::EINVAL),
                    Err(()) => break,
                }
            }
            if !out.is_empty() {
                return Ok(Some(out));
            }
            if nonblock { Err(Errno::EAGAIN) } else { Ok(None) }
        })?;
        buf[..out.len()].copy_from_slice(&out);
        Ok(out.len())
    }

    fn ioctl(&self, _file: &File, cmd: u32, arg: usize, mem: &dyn UserMemory) -> Result<usize> {
        if cmd != FIONREAD {
            return Err(Errno::ENOTTY);
        }
        let bytes = self.group.state.lock().queue.bytes() as i32;
        mem.write(arg, &bytes.to_ne_bytes())?;
        Ok(0)
    }

    fn poll_wait(&self, _file: &File, table: &mut PollTable) {
        table.add(&self.group.wait);
    }

    fn poll(&self, _file: &File) -> u32 {
        if self.group.state.lock().queue.is_empty() { 0 } else { events::POLLIN }
    }

    fn pollable(&self) -> bool {
        true
    }

    fn event_count(&self) -> u64 {
        self.group.events.load(Ordering::Relaxed)
    }

    fn fdinfo(&self, _file: &File) -> Vec<u8> {
        self.group.fdinfo()
    }

    fn as_any(&self) -> Option<&dyn core::any::Any> {
        Some(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_device_has_the_encoding_of_the_kernel() {
        // 8:1 in the encoding of `stat` is 0x801, and `MKDEV(8, 1)` is 0x800001.
        assert_eq!(kernel_dev(0x801), 0x80_0001);
        assert_eq!(kernel_dev(0), 0);
    }
}
