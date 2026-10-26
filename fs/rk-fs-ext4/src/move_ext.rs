//! The swap of the blocks of two files for online defragmentation, as `EXT4_IOC_MOVE_EXT` and
//! `ext4_move_extents` of Linux. The data of the original file stays the same, but it goes to
//! the blocks of the donor file. The donor file gets the old blocks of the original file.

use crate::extent::{self, Extent};
use crate::layout::{RawInode, flags};
use crate::{Fs, Tx};
use alloc::vec;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_vfs::Result;
use rk_vfs::inode::iflags;

/// The size of a page, for the check of the start blocks.
const PAGE_SIZE: u64 = 4096;
/// The first block that an extent cannot map, as `EXT_MAX_BLOCKS` of Linux.
const EXT_MAX_BLOCKS: u64 = 0xffff_ffff;
/// The most blocks that one copy of data reads and writes.
const COPY_BLOCKS: u64 = 64;

/// A run of blocks that moves: blocks of the original file and the donor file that both have an
/// extent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Pair {
    /// The first block of the original file.
    pub orig: u32,
    /// The first block of the donor file.
    pub donor: u32,
    /// The number of blocks.
    pub len: u32,
    /// The first block of the disk of the original file, and if the blocks have data.
    pub orig_at: (u64, bool),
    /// The first block of the disk of the donor file, and if the blocks have data.
    pub donor_at: (u64, bool),
}

/// Gives the extent of the sorted list that has `lblock`, or else the next extent after it.
fn at_or_after(extents: &[Extent], lblock: u64) -> Option<&Extent> {
    extents.get(extents.partition_point(|e| e.end() <= lblock))
}

/// Finds the runs of blocks that move in the blocks `orig_start..orig_start + len` of the
/// original file. Block `orig_start + i` of the original file goes with block `donor_start + i`
/// of the donor file. A run moves only if both files have an extent there, as Linux skips a
/// hole in each file.
pub(crate) fn pairs(
    orig: &[Extent],
    donor: &[Extent],
    orig_start: u64,
    donor_start: u64,
    len: u64,
) -> Vec<Pair> {
    let end = orig_start + len;
    let mut out = Vec::new();
    let mut x = orig_start;
    while x < end {
        let Some(o) = at_or_after(orig, x) else { break };
        if u64::from(o.lblock) > x {
            x = u64::from(o.lblock);
            continue;
        }
        let y = x - orig_start + donor_start;
        let left = (o.end() - x).min(end - x);
        let Some(d) = at_or_after(donor, y) else { break };
        if u64::from(d.lblock) > y {
            x += left.min(u64::from(d.lblock) - y);
            continue;
        }
        let n = left.min(d.end() - y);
        out.push(Pair {
            orig: x as u32,
            donor: y as u32,
            len: n as u32,
            orig_at: (o.start + (x - u64::from(o.lblock)), o.init),
            donor_at: (d.start + (y - u64::from(d.lblock)), d.init),
        });
        x += n;
    }
    out
}

/// Checks the two files, as `mext_check_validity` of Linux, in its order.
fn check(orig_ino: u32, orig: &RawInode, donor_ino: u32, donor: &RawInode) -> Result<()> {
    const REGULAR: u16 = 0o100000;
    if orig_ino == donor_ino {
        return Err(Errno::EINVAL);
    }
    if orig.mode() & 0o170000 != REGULAR || donor.mode() & 0o170000 != REGULAR {
        return Err(Errno::EINVAL);
    }
    if orig.flags() & flags::DAX != 0 {
        return Err(Errno::EOPNOTSUPP);
    }
    if (orig.flags() | donor.flags()) & flags::ENCRYPT != 0 {
        return Err(Errno::EOPNOTSUPP);
    }
    if orig.flags() & donor.flags() & flags::EXTENTS == 0 {
        return Err(Errno::EOPNOTSUPP);
    }
    if donor.mode() & 0o6000 != 0 {
        return Err(Errno::EINVAL);
    }
    if donor.flags() & (iflags::IMMUTABLE | iflags::APPEND) != 0 {
        return Err(Errno::EPERM);
    }
    if orig.size() == 0 || donor.size() == 0 {
        return Err(Errno::EINVAL);
    }
    Ok(())
}

impl Fs {
    /// Checks the range of a move, and gives its length in blocks up to the end of the shorter
    /// file, as `mext_check_adjust_range` of Linux. As Linux, a length of 0 from block 0 gives
    /// the length of the file.
    fn move_range(
        &self,
        orig: &RawInode,
        donor: &RawInode,
        orig_start: u64,
        donor_start: u64,
        len: u64,
    ) -> Result<u64> {
        let bs = self.sb.block_size;
        let mask = (PAGE_SIZE / bs).max(1) - 1;
        if orig_start & mask != donor_start & mask {
            return Err(Errno::EINVAL);
        }
        if orig_start >= EXT_MAX_BLOCKS
            || donor_start >= EXT_MAX_BLOCKS
            || len > EXT_MAX_BLOCKS
            || donor_start + len >= EXT_MAX_BLOCKS
            || orig_start + len >= EXT_MAX_BLOCKS
        {
            return Err(Errno::EINVAL);
        }
        let mut len = len;
        for (eof, start) in
            [(orig.size().div_ceil(bs), orig_start), (donor.size().div_ceil(bs), donor_start)]
        {
            if eof <= start {
                len = 0;
            } else if eof < (start + len).wrapping_sub(1) {
                len = eof - start;
            }
        }
        if len == 0 {
            return Err(Errno::EINVAL);
        }
        Ok(len)
    }
}

impl Tx<'_> {
    /// Swaps the blocks `orig_start..orig_start + len` of the file `orig_ino` with the blocks
    /// from `donor_start` of the file `donor_ino`, and gives the number of blocks that moved.
    /// If the blocks of both files have no data, only the extents swap. Otherwise the data of
    /// the original file goes to the blocks of the donor file first, and these blocks then have
    /// data in the original file. The donor file gets the old blocks of the original file, with
    /// their data. A hole in either file stays.
    ///
    /// # Errors
    ///
    /// Gives `EINVAL` for the same file, a file that is not regular, an empty file, a donor
    /// file with `S_ISUID` or `S_ISGID`, or a bad range, `EOPNOTSUPP` for a file without an
    /// extent tree, an encrypted file or a DAX file, `EPERM` for an immutable or append-only
    /// donor file, `ENOSPC` if a tree does not fit, or the error of the disk.
    pub(crate) fn move_extents(
        &mut self,
        (orig_ino, orig): (u32, &mut RawInode),
        (donor_ino, donor): (u32, &mut RawInode),
        orig_start: u64,
        donor_start: u64,
        len: u64,
    ) -> Result<u64> {
        let fs = self.fs;
        check(orig_ino, orig, donor_ino, donor)?;
        let len = fs.move_range(orig, donor, orig_start, donor_start, len)?;
        let (old, orig_tree) = fs.extents(orig)?;
        let (mut donor_list, donor_tree) = fs.extents(donor)?;
        let found = pairs(&old, &donor_list, orig_start, donor_start, len);
        if found.is_empty() {
            return Ok(0);
        }
        let bs = fs.sb.block_size;
        let mut orig_list = old.clone();
        let mut moved = 0;
        for p in &found {
            // The data goes to the blocks of the donor first, so a crash before the commit
            // keeps the old blocks of the original file.
            let copy = p.orig_at.1 || p.donor_at.1;
            if copy {
                let mut done = 0;
                while done < u64::from(p.len) {
                    let n = (u64::from(p.len) - done).min(COPY_BLOCKS);
                    let mut buf = vec![0u8; (n * bs) as usize];
                    if p.orig_at.1 {
                        fs.read((p.orig_at.0 + done) * bs, &mut buf)?;
                    }
                    fs.write_file(orig, (p.donor_at.0 + done) * bs, &buf)?;
                    done += n;
                }
            }
            let (o, d) = (p.orig_at, p.donor_at);
            extent::put(
                &mut orig_list,
                Extent { lblock: p.orig, len: p.len, start: d.0, init: copy },
            );
            extent::put(
                &mut donor_list,
                Extent { lblock: p.donor, len: p.len, start: o.0, init: o.1 },
            );
            moved += u64::from(p.len);
        }
        self.build_tree(orig_ino, orig, &orig_list, orig_tree)?;
        if let Err(e) = self.build_tree(donor_ino, donor, &donor_list, donor_tree) {
            // The original file gets its old extents back, in the blocks of its new tree.
            let (_, tree) = fs.extents(orig)?;
            self.build_tree(orig_ino, orig, &old, tree)?;
            return Err(e);
        }
        Ok(moved)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ext(lblock: u32, len: u32, start: u64, init: bool) -> Extent {
        Extent { lblock, len, start, init }
    }

    #[test]
    fn pairs_skip_the_holes_of_both_files() {
        let orig = [ext(0, 4, 100, true), ext(10, 2, 200, false)];
        let donor = [ext(2, 20, 500, false)];
        assert_eq!(
            pairs(&orig, &donor, 0, 0, 12),
            [
                Pair { orig: 2, donor: 2, len: 2, orig_at: (102, true), donor_at: (500, false) },
                Pair { orig: 10, donor: 10, len: 2, orig_at: (200, false), donor_at: (508, false) },
            ]
        );
        // The donor blocks start at a different place, and the length cuts the last run.
        assert_eq!(
            pairs(&orig, &donor, 1, 5, 2),
            [Pair { orig: 1, donor: 5, len: 2, orig_at: (101, true), donor_at: (503, false) }]
        );
        assert!(pairs(&orig, &donor, 4, 4, 6).is_empty());
        assert!(pairs(&orig, &[], 0, 0, 12).is_empty());
    }

    #[test]
    fn pairs_split_at_the_ends_of_the_donor_extents() {
        let orig = [ext(0, 6, 100, true)];
        let donor = [ext(0, 2, 300, false), ext(3, 5, 400, true)];
        assert_eq!(
            pairs(&orig, &donor, 0, 0, 6),
            [
                Pair { orig: 0, donor: 0, len: 2, orig_at: (100, true), donor_at: (300, false) },
                Pair { orig: 3, donor: 3, len: 3, orig_at: (103, true), donor_at: (400, true) },
            ]
        );
    }
}
