//! The file descriptor table of a process.

use crate::file::File;
use crate::inode::Result;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use rk_abi::Errno;

/// The default of `RLIMIT_NOFILE`, as Linux.
pub const NR_OPEN_DEFAULT: usize = 1024;

/// One descriptor.
#[derive(Clone, Debug)]
pub struct FdEntry {
    /// The open file.
    pub file: Arc<File>,
    /// `FD_CLOEXEC`: `execve` closes the descriptor.
    pub cloexec: bool,
}

/// The work of the close of a descriptor of `file` in the table `owner`, as Linux does it: the
/// POSIX locks of the table on the file go, and so does the dnotify entry.
fn on_close(file: &Arc<File>, owner: usize) {
    crate::lock::close_posix(file, owner);
    crate::notify::dnotify::flush(file, owner);
}

/// The next owner number of a table. The owner of the POSIX record locks is the table, as Linux.
static NEXT_OWNER: AtomicUsize = AtomicUsize::new(1);

/// The descriptors of a process. `fork` copies the table, and `clone` with `CLONE_FILES` shares it.
#[derive(Debug)]
pub struct FdTable {
    entries: Vec<Option<FdEntry>>,
    /// No descriptor below it is free, as `next_fd` of Linux, so a new descriptor does not
    /// walk all the open ones.
    next_free: usize,
    limit: usize,
    owner: usize,
}

impl Clone for FdTable {
    /// Copies the descriptors. The copy is a new owner, so it does not get the POSIX locks of
    /// the table, as `fork` on Linux.
    fn clone(&self) -> Self {
        Self {
            entries: self.entries.clone(),
            next_free: self.next_free,
            limit: self.limit,
            owner: NEXT_OWNER.fetch_add(1, Ordering::Relaxed),
        }
    }
}

impl Drop for FdTable {
    fn drop(&mut self) {
        for entry in self.entries.iter().flatten() {
            on_close(&entry.file, self.owner);
        }
    }
}

impl Default for FdTable {
    fn default() -> Self {
        Self::new()
    }
}

impl FdTable {
    /// Makes an empty table.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            next_free: 0,
            limit: NR_OPEN_DEFAULT,
            owner: NEXT_OWNER.fetch_add(1, Ordering::Relaxed),
        }
    }

    /// Sets the number of descriptors that the table gives, the soft `RLIMIT_NOFILE` of the
    /// process. The descriptors at `limit` or above stay open, as on Linux.
    pub fn set_limit(&mut self, limit: usize) {
        self.limit = limit;
    }

    /// The owner of the POSIX record locks that the process takes through this table.
    pub fn owner(&self) -> usize {
        self.owner
    }

    /// Gives the entry of `fd`.
    pub fn get(&self, fd: i32) -> Result<&FdEntry> {
        usize::try_from(fd)
            .ok()
            .and_then(|i| self.entries.get(i))
            .and_then(Option::as_ref)
            .ok_or(Errno::EBADF)
    }

    /// Gives the file of `fd`.
    pub fn file(&self, fd: i32) -> Result<Arc<File>> {
        self.get(fd).map(|e| e.file.clone())
    }

    /// Adds `file` at the lowest free descriptor that is `min` or more, and gives the
    /// descriptor.
    pub fn insert_from(&mut self, min: usize, file: Arc<File>, cloexec: bool) -> Result<i32> {
        if min >= self.limit {
            return Err(Errno::EINVAL);
        }
        let start = min.max(self.next_free);
        let free = (start..self.entries.len()).find(|&i| self.entries[i].is_none());
        let fd = free.unwrap_or(self.entries.len().max(start));
        if fd >= self.limit {
            return Err(Errno::EMFILE);
        }
        if fd >= self.entries.len() {
            self.entries.resize(fd + 1, None);
        }
        self.entries[fd] = Some(FdEntry { file, cloexec });
        if min <= self.next_free {
            self.next_free = fd + 1;
        }
        Ok(fd as i32)
    }

    /// Adds `file` at the lowest free descriptor. A limit of 0 gives `EMFILE`, as on Linux, and
    /// not the `EINVAL` of `insert_from`.
    pub fn insert(&mut self, file: Arc<File>, cloexec: bool) -> Result<i32> {
        if self.limit == 0 {
            return Err(Errno::EMFILE);
        }
        self.insert_from(0, file, cloexec)
    }

    /// Puts `file` at `fd`, as `dup2` does. Gives the file that was at `fd`, so the caller can
    /// drop it outside a lock.
    pub fn set(&mut self, fd: i32, file: Arc<File>, cloexec: bool) -> Result<Option<FdEntry>> {
        let i = usize::try_from(fd).map_err(|_| Errno::EBADF)?;
        if i >= self.limit {
            return Err(Errno::EBADF);
        }
        if i >= self.entries.len() {
            self.entries.resize(i + 1, None);
        }
        let old = self.entries[i].replace(FdEntry { file, cloexec });
        if let Some(e) = &old {
            on_close(&e.file, self.owner);
        }
        Ok(old)
    }

    /// Adds `file` at the lowest free descriptor below `limit`, the `RLIMIT_NOFILE` of the
    /// process that gets the file.
    pub fn insert_limited(&mut self, file: Arc<File>, cloexec: bool, limit: usize) -> Result<i32> {
        let free = (self.next_free..self.entries.len()).find(|&i| self.entries[i].is_none());
        if free.unwrap_or(self.entries.len()) >= limit.min(self.limit) {
            return Err(Errno::EMFILE);
        }
        self.insert(file, cloexec)
    }

    /// Puts `file` at `fd`, as `set` does, if `fd` is below `limit`, the `RLIMIT_NOFILE` of the
    /// process that gets the file.
    pub fn set_limited(
        &mut self,
        fd: i32,
        file: Arc<File>,
        cloexec: bool,
        limit: usize,
    ) -> Result<Option<FdEntry>> {
        if usize::try_from(fd).map_or(true, |i| i >= limit) {
            return Err(Errno::EBADF);
        }
        self.set(fd, file, cloexec)
    }

    /// Removes `fd` and gives its entry.
    pub fn remove(&mut self, fd: i32) -> Result<FdEntry> {
        let i = usize::try_from(fd).map_err(|_| Errno::EBADF)?;
        let entry = self.entries.get_mut(i).and_then(Option::take).ok_or(Errno::EBADF)?;
        self.next_free = self.next_free.min(i);
        while self.entries.last().is_some_and(Option::is_none) {
            self.entries.pop();
        }
        on_close(&entry.file, self.owner);
        Ok(entry)
    }

    /// Sets `FD_CLOEXEC` of `fd`.
    pub fn set_cloexec(&mut self, fd: i32, cloexec: bool) -> Result<()> {
        let entry = usize::try_from(fd)
            .ok()
            .and_then(|i| self.entries.get_mut(i))
            .and_then(Option::as_mut)
            .ok_or(Errno::EBADF)?;
        entry.cloexec = cloexec;
        Ok(())
    }

    /// Removes each descriptor with `FD_CLOEXEC`, for `execve`. Gives the removed entries.
    pub fn close_on_exec(&mut self) -> Vec<FdEntry> {
        let mut closed = Vec::new();
        self.next_free = 0;
        for slot in &mut self.entries {
            if slot.as_ref().is_some_and(|e| e.cloexec)
                && let Some(entry) = slot.take()
            {
                on_close(&entry.file, self.owner);
                closed.push(entry);
            }
        }
        closed
    }

    /// Copies the table for `execve`. The copy keeps the POSIX locks, as Linux keeps them over
    /// `execve`, and this table becomes a new owner without locks.
    pub fn clone_for_exec(&mut self) -> Self {
        let mut copy = self.clone();
        core::mem::swap(&mut copy.owner, &mut self.owner);
        copy
    }

    /// Removes each descriptor in `first..=last`, for `close_range`.
    pub fn remove_range(&mut self, first: usize, last: usize) -> Vec<FdEntry> {
        let end = self.entries.len().min(last.saturating_add(1));
        let closed: Vec<FdEntry> = (first..end).filter_map(|i| self.entries[i].take()).collect();
        self.next_free = self.next_free.min(first);
        for e in &closed {
            on_close(&e.file, self.owner);
        }
        while self.entries.last().is_some_and(Option::is_none) {
            self.entries.pop();
        }
        closed
    }

    /// The descriptors in order, with their entries.
    pub fn iter(&self) -> impl Iterator<Item = (i32, &FdEntry)> {
        self.entries.iter().enumerate().filter_map(|(i, e)| Some((i as i32, e.as_ref()?)))
    }
}
