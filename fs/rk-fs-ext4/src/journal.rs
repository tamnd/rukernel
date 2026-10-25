//! The replay of the jbd2 journal. A transaction in the log has descriptor blocks, each followed
//! by the copies of the blocks that its tags name, revoke blocks, and a commit block. The replay
//! reads the log in three passes, as `jbd2_journal_recover` of Linux: the first pass finds the
//! last transaction with a valid commit block, the second pass reads the revoke records, and the
//! third pass writes the copies to their blocks. A copy that a later revoke record names is not
//! written. The fields of the journal are big endian.

use crate::layout::RawInode;
use crate::{Fs, crc};
use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_vfs::Result;

/// The magic number at the start of each block of the journal that is not a copy.
pub(crate) const MAGIC: u32 = 0xc03b_3998;

/// The types of the blocks of the journal.
mod kind {
    pub(crate) const DESCRIPTOR: u32 = 1;
    pub(crate) const COMMIT: u32 = 2;
    pub(crate) const SUPERBLOCK_V1: u32 = 3;
    pub(crate) const SUPERBLOCK_V2: u32 = 4;
    pub(crate) const REVOKE: u32 = 5;
}

/// The incompatible features of the journal.
pub(crate) mod feature {
    pub(crate) const REVOKE: u32 = 0x1;
    pub(crate) const BIT64: u32 = 0x2;
    pub(crate) const ASYNC_COMMIT: u32 = 0x4;
    pub(crate) const CSUM_V2: u32 = 0x8;
    pub(crate) const CSUM_V3: u32 = 0x10;
    /// The features that the replay supports.
    pub(crate) const SUPPORTED: u32 = REVOKE | BIT64 | ASYNC_COMMIT | CSUM_V2 | CSUM_V3;
}

/// The flags of a tag.
mod tag {
    /// The first 4 bytes of the copy were the magic number, and the log has zeros there.
    pub(crate) const ESCAPE: u32 = 0x1;
    /// The tag has no UUID after it.
    pub(crate) const SAME_UUID: u32 = 0x2;
    /// The last tag of the descriptor block.
    pub(crate) const LAST: u32 = 0x8;
}

/// The offsets of the fields of the journal superblock.
pub(crate) mod jsb {
    pub(crate) const BLOCK_SIZE: usize = 0xc;
    pub(crate) const MAX_LEN: usize = 0x10;
    pub(crate) const FIRST: usize = 0x14;
    pub(crate) const SEQUENCE: usize = 0x18;
    pub(crate) const START: usize = 0x1c;
    pub(crate) const INCOMPAT: usize = 0x28;
    pub(crate) const UUID: usize = 0x30;
    pub(crate) const CHECKSUM: usize = 0xfc;
    /// The length of the superblock that the checksum covers.
    pub(crate) const SIZE: usize = 1024;
}

pub(crate) fn be32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

pub(crate) fn put_be32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_be_bytes());
}

/// Tells if the transaction `a` comes after the transaction `b`, with wrap around.
fn after(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}

/// One tag of a descriptor block.
struct Tag {
    block: u64,
    flags: u32,
    csum: u32,
}

/// The pass of the replay.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Pass {
    Scan,
    Revoke,
    Replay,
}

/// The journal of a file system that has a log to replay.
pub(crate) struct Journal<'a> {
    fs: &'a Fs,
    inode: RawInode,
    bs: usize,
    sb: Vec<u8>,
    max_len: u32,
    first: u32,
    incompat: u32,
    /// The seed of the checksums, for `CSUM_V2` and `CSUM_V3`.
    seed: u32,
}

impl<'a> Journal<'a> {
    /// Reads the journal superblock of the inode `ino`.
    pub(crate) fn open(fs: &'a Fs, ino: u32) -> Result<Self> {
        let inode = fs.read_inode(ino)?;
        let bs = fs.sb.block_size as usize;
        let mut journal =
            Self { fs, inode, bs, sb: Vec::new(), max_len: 0, first: 0, incompat: 0, seed: 0 };
        let sb = journal.read(0)?;
        let v2 = match (be32(&sb, 0), be32(&sb, 4)) {
            (MAGIC, kind::SUPERBLOCK_V1) => false,
            (MAGIC, kind::SUPERBLOCK_V2) => true,
            _ => return Err(Errno::EUCLEAN),
        };
        if be32(&sb, jsb::BLOCK_SIZE) as usize != bs {
            return Err(Errno::EUCLEAN);
        }
        journal.incompat = if v2 { be32(&sb, jsb::INCOMPAT) } else { 0 };
        if journal.incompat & !feature::SUPPORTED != 0 {
            return Err(Errno::EOPNOTSUPP);
        }
        journal.max_len = be32(&sb, jsb::MAX_LEN);
        journal.first = be32(&sb, jsb::FIRST);
        if journal.first == 0 || journal.first >= journal.max_len {
            return Err(Errno::EUCLEAN);
        }
        if journal.csum() {
            if crc::crc32c(!0, &zeroed(&sb[..jsb::SIZE], jsb::CHECKSUM)) != be32(&sb, jsb::CHECKSUM)
            {
                return Err(Errno::EUCLEAN);
            }
            journal.seed = crc::crc32c(!0, &sb[jsb::UUID..jsb::UUID + 16]);
        }
        journal.sb = sb;
        Ok(journal)
    }

    fn csum(&self) -> bool {
        self.incompat & (feature::CSUM_V2 | feature::CSUM_V3) != 0
    }

    fn v3(&self) -> bool {
        self.incompat & feature::CSUM_V3 != 0
    }

    /// The block of the disk that has the block `n` of the journal.
    fn map(&self, n: u32) -> Result<u64> {
        match self.fs.map(&self.inode, u64::from(n))? {
            Some((block, true)) => Ok(block),
            _ => Err(Errno::EUCLEAN),
        }
    }

    fn read(&self, n: u32) -> Result<Vec<u8>> {
        self.fs.read_block(self.map(n)?)
    }

    fn write(&self, n: u32, data: &[u8]) -> Result<()> {
        self.fs.write(self.map(n)? * self.bs as u64, data)
    }

    /// The block of the log after `n`.
    fn next(&self, n: u32) -> u32 {
        if n + 1 >= self.max_len { self.first } else { n + 1 }
    }

    /// The length of a tag, as `journal_tag_bytes` of Linux.
    fn tag_bytes(&self) -> usize {
        if self.v3() {
            return 16;
        }
        let size = if self.incompat & feature::CSUM_V2 != 0 { 14 } else { 12 };
        if self.incompat & feature::BIT64 != 0 { size } else { size - 4 }
    }

    /// Tells if the checksum in the last 4 bytes of a descriptor or a revoke block is right.
    fn tail_ok(&self, block: &[u8]) -> bool {
        let at = block.len() - 4;
        !self.csum() || crc::crc32c(self.seed, &zeroed(block, at)) == be32(block, at)
    }

    /// Tells if the checksum of a commit block is right.
    fn commit_ok(&self, block: &[u8]) -> bool {
        !self.csum() || crc::crc32c(self.seed, &zeroed(block, 16)) == be32(block, 16)
    }

    /// Tells if the copy `data` of the transaction `seq` has the checksum of its tag.
    fn data_ok(&self, tag: &Tag, seq: u32, data: &[u8]) -> bool {
        if !self.csum() {
            return true;
        }
        let csum = crc::crc32c(crc::crc32c(self.seed, &seq.to_be_bytes()), data);
        if self.v3() { csum == tag.csum } else { csum & 0xffff == tag.csum }
    }

    /// The tags of a descriptor block.
    fn tags(&self, block: &[u8]) -> Vec<Tag> {
        let limit = block.len() - if self.csum() { 4 } else { 0 };
        let size = self.tag_bytes();
        let bit64 = self.incompat & feature::BIT64 != 0;
        let mut tags = Vec::new();
        let mut at = 12;
        while at + size <= limit {
            let t = &block[at..at + size];
            let (flags, csum, high) = if self.v3() {
                (be32(t, 4), be32(t, 12), be32(t, 8))
            } else {
                let csum = u32::from(u16::from_be_bytes([t[4], t[5]]));
                let flags = u32::from(u16::from_be_bytes([t[6], t[7]]));
                (flags, csum, if bit64 { be32(t, 8) } else { 0 })
            };
            let high = if bit64 { u64::from(high) << 32 } else { 0 };
            tags.push(Tag { block: high | u64::from(be32(t, 0)), flags, csum });
            at += size;
            if flags & tag::SAME_UUID == 0 {
                at += 16;
            }
            if flags & tag::LAST != 0 {
                break;
            }
        }
        tags
    }

    /// Runs one pass over the log. Gives the transaction after the last one with a valid commit
    /// block.
    fn pass(&self, pass: Pass, end: u32, revoked: &mut BTreeMap<u64, u32>) -> Result<u32> {
        let mut seq = be32(&self.sb, jsb::SEQUENCE);
        let mut n = be32(&self.sb, jsb::START);
        // The log can hold at most one block of each position.
        for _ in 0..self.max_len {
            if pass != Pass::Scan && !after(end, seq) {
                break;
            }
            let block = self.read(n)?;
            if be32(&block, 0) != MAGIC || be32(&block, 8) != seq {
                break;
            }
            match be32(&block, 4) {
                kind::DESCRIPTOR => {
                    if !self.tail_ok(&block) {
                        break;
                    }
                    for tag in self.tags(&block) {
                        n = self.next(n);
                        if pass != Pass::Replay {
                            continue;
                        }
                        if revoked.get(&tag.block).is_some_and(|&r| !after(seq, r)) {
                            continue;
                        }
                        let mut data = self.read(n)?;
                        // A copy with a bad checksum is not written, as Linux does.
                        if !self.data_ok(&tag, seq, &data) {
                            continue;
                        }
                        if tag.flags & tag::ESCAPE != 0 {
                            put_be32(&mut data, 0, MAGIC);
                        }
                        if tag.block >= self.fs.sb.blocks_count {
                            return Err(Errno::EUCLEAN);
                        }
                        self.fs.write(tag.block * self.bs as u64, &data)?;
                    }
                }
                kind::COMMIT => {
                    if !self.commit_ok(&block) {
                        break;
                    }
                    seq = seq.wrapping_add(1);
                }
                kind::REVOKE => {
                    if !self.tail_ok(&block) {
                        break;
                    }
                    if pass == Pass::Revoke {
                        let size = if self.incompat & feature::BIT64 != 0 { 8 } else { 4 };
                        let count = (be32(&block, 12) as usize)
                            .min(block.len() - if self.csum() { 4 } else { 0 });
                        let mut at = 16;
                        while at + size <= count {
                            let target = if size == 8 {
                                u64::from(be32(&block, at)) << 32 | u64::from(be32(&block, at + 4))
                            } else {
                                u64::from(be32(&block, at))
                            };
                            let r = revoked.entry(target).or_insert(seq);
                            if after(seq, *r) {
                                *r = seq;
                            }
                            at += size;
                        }
                    }
                }
                _ => break,
            }
            n = self.next(n);
        }
        Ok(seq)
    }

    /// Replays the log, and then marks the journal empty.
    pub(crate) fn replay(&self) -> Result<()> {
        let mut revoked = BTreeMap::new();
        if be32(&self.sb, jsb::START) != 0 {
            let end = self.pass(Pass::Scan, 0, &mut revoked)?;
            self.pass(Pass::Revoke, end, &mut revoked)?;
            self.pass(Pass::Replay, end, &mut revoked)?;
            let mut sb = self.read(0)?;
            put_be32(&mut sb, jsb::SEQUENCE, end.wrapping_add(1));
            put_be32(&mut sb, jsb::START, 0);
            if self.csum() {
                let csum = crc::crc32c(!0, &zeroed(&sb[..jsb::SIZE], jsb::CHECKSUM));
                put_be32(&mut sb, jsb::CHECKSUM, csum);
            }
            self.write(0, &sb)?;
        }
        Ok(())
    }
}

/// A copy of `b` with zeros in the 4 bytes at `at`.
fn zeroed(b: &[u8], at: usize) -> Vec<u8> {
    let mut copy = b.to_vec();
    copy[at..at + 4].fill(0);
    copy
}

impl Fs {
    /// Replays the journal of a file system with `RECOVER`, and clears `RECOVER`.
    pub(crate) fn recover(&self) -> Result<()> {
        if self.sb.incompat & crate::layout::incompat::JOURNAL_DEV != 0 || self.sb.journal_inum == 0
        {
            return Err(Errno::EOPNOTSUPP);
        }
        Journal::open(self, self.sb.journal_inum)?.replay()?;
        // The log can have a copy of the superblock, so the flag is cleared in the new one.
        let mut b = vec![0u8; crate::layout::SUPERBLOCK_SIZE];
        self.read(crate::layout::SUPERBLOCK_AT, &mut b)?;
        let incompat = crate::layout::u32_at(&b, 0x60) & !crate::layout::incompat::RECOVER;
        crate::layout::put32(&mut b, 0x60, incompat);
        if self.metadata_csum() {
            let at = crate::layout::sb::CHECKSUM;
            let csum = crc::crc32c(!0, &b[..at]);
            crate::layout::put32(&mut b, at, csum);
        }
        self.write(crate::layout::SUPERBLOCK_AT, &b)
    }
}
