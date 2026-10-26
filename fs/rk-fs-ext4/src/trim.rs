//! The discard of the free blocks of a mounted file system, as `FITRIM` and `ext4_trim_fs` of
//! Linux.

use crate::Fs;
use crate::alloc_blocks::test_bit;
use rk_abi::Errno;
use rk_vfs::Result;

impl Fs {
    /// Discards the runs of free blocks from the byte `start` up to `start + len` that have at
    /// least `minlen` bytes, and gives the bytes in the runs. A block that was freed since the
    /// last commit stays, because the journal can still need its data.
    ///
    /// # Errors
    ///
    /// Gives `EOPNOTSUPP` if the disk cannot discard, `EINVAL` if `start` is past the end, `len`
    /// is less than a block or `minlen` is more than a group, `EROFS` for a read only mount, or
    /// the error of the disk.
    pub(crate) fn trim(&self, start: u64, len: u64, minlen: u64) -> Result<u64> {
        if !self.disk.can_discard() {
            return Err(Errno::EOPNOTSUPP);
        }
        let sb = &self.sb;
        let bs = sb.block_size;
        let bits = bs.trailing_zeros();
        let max = self.blocks_count();
        let first_data = u64::from(sb.first_data_block);
        let per_group = u64::from(sb.blocks_per_group);
        let mut start = start >> bits;
        let minlen = (minlen >> bits).max(1);
        if minlen > per_group || start >= max || len < bs {
            return Err(Errno::EINVAL);
        }
        let end = start.saturating_add(len >> bits).saturating_sub(1).min(max - 1);
        if end <= first_data {
            return Ok(0);
        }
        start = start.max(first_data);
        let mut trimmed = 0;
        let (first_group, last_group) =
            ((start - first_data) / per_group, (end - first_data) / per_group);
        for group in first_group..=last_group {
            let group = u32::try_from(group).map_err(|_| Errno::EIO)?;
            // The lock stops an allocation in the group while its free blocks go.
            let tx = self.tx()?;
            let bitmap = tx.block_bitmap(group)?;
            let base = first_data + u64::from(group) * per_group;
            let from = start.max(base) - base;
            let to = (end - base).min(u64::from(self.blocks_in_group(group)) - 1);
            let mut run: Option<u64> = None;
            for bit in from..=to + 1 {
                let free =
                    bit <= to && !test_bit(&bitmap, bit as usize) && !self.is_busy(base + bit);
                match (free, run) {
                    (true, None) => run = Some(bit),
                    (false, Some(first)) => {
                        run = None;
                        let count = bit - first;
                        if count >= minlen {
                            self.disk.discard((base + first) * bs, count * bs)?;
                            trimmed += count;
                        }
                    }
                    _ => {}
                }
            }
            drop(tx);
        }
        Ok(trimmed * bs)
    }
}
