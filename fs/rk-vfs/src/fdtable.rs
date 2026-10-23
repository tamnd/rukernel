//! The file descriptor table of a process.

use crate::file::File;
use crate::inode::Result;
use alloc::sync::Arc;
use alloc::vec::Vec;
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

/// The descriptors of a process. `fork` copies the table, and `clone` with `CLONE_FILES` shares it.
#[derive(Clone, Debug)]
pub struct FdTable {
    entries: Vec<Option<FdEntry>>,
    limit: usize,
}

impl Default for FdTable {
    fn default() -> Self {
        Self::new()
    }
}

impl FdTable {
    /// Makes an empty table.
    pub const fn new() -> Self {
        Self { entries: Vec::new(), limit: NR_OPEN_DEFAULT }
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
        let free = (min..self.entries.len()).find(|&i| self.entries[i].is_none());
        let fd = free.unwrap_or(self.entries.len().max(min));
        if fd >= self.limit {
            return Err(Errno::EMFILE);
        }
        if fd >= self.entries.len() {
            self.entries.resize(fd + 1, None);
        }
        self.entries[fd] = Some(FdEntry { file, cloexec });
        Ok(fd as i32)
    }

    /// Adds `file` at the lowest free descriptor.
    pub fn insert(&mut self, file: Arc<File>, cloexec: bool) -> Result<i32> {
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
        Ok(self.entries[i].replace(FdEntry { file, cloexec }))
    }

    /// Removes `fd` and gives its entry.
    pub fn remove(&mut self, fd: i32) -> Result<FdEntry> {
        let entry = usize::try_from(fd)
            .ok()
            .and_then(|i| self.entries.get_mut(i))
            .and_then(Option::take)
            .ok_or(Errno::EBADF)?;
        while self.entries.last().is_some_and(Option::is_none) {
            self.entries.pop();
        }
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
        for slot in &mut self.entries {
            if slot.as_ref().is_some_and(|e| e.cloexec)
                && let Some(entry) = slot.take()
            {
                closed.push(entry);
            }
        }
        closed
    }

    /// Removes each descriptor in `first..=last`, for `close_range`.
    pub fn remove_range(&mut self, first: usize, last: usize) -> Vec<FdEntry> {
        let end = self.entries.len().min(last.saturating_add(1));
        let closed = (first..end).filter_map(|i| self.entries[i].take()).collect();
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
