//! The htree index of a large directory, `dir_index`, as fs/ext4/namei.c and fs/ext4/hash.c of
//! Linux.
//!
//! The block 0 of an indexed directory is the root. It has `.` and a `..` that covers the rest
//! of the block, and after them the root information and a list of `(hash, block)` entries. An
//! index entry points to a leaf block, or to a node block with more entries. A node block starts
//! with an empty record that covers the block. The first entry of a list has the count and the
//! limit of the list in place of the hash. The entries of a leaf have a hash that is at least the
//! hash of its index entry, and less than the hash of the next one. The low bit of a hash in the
//! index tells that the leaf before has names with the same hash. With `metadata_csum`, each
//! index block has a checksum after the last possible entry, the `dx_tail`.

use crate::dir::{rec_len, search_block};
use crate::layout::{self, RawInode, flags, put16, put32, u16_at, u32_at};
use crate::node::Node;
use crate::{Fs, Tx, crc};
use alloc::vec;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_vfs::{FileType, Result};

/// The length of the `dx_tail` with the checksum of an index block.
const DX_TAIL: usize = 8;
/// The offset of the root information in the block 0.
const INFO: usize = 24;
/// The length of the root information.
const INFO_LEN: usize = 8;
/// The hash that marks the end of a directory for a 32-bit `readdir`, `EXT4_HTREE_EOF_32BIT`.
const EOF_32BIT: u32 = 0x7fff_ffff;

/// The names of the hash versions, `DX_HASH_*`.
mod version {
    /// The legacy hash, `dx_hack_hash`.
    pub(super) const LEGACY: u8 = 0;
    /// The half MD4 hash.
    pub(super) const HALF_MD4: u8 = 1;
    /// The TEA hash.
    pub(super) const TEA: u8 = 2;
    /// The legacy hash of the bytes as unsigned numbers.
    pub(super) const LEGACY_UNSIGNED: u8 = 3;
    /// The half MD4 hash of the bytes as unsigned numbers.
    pub(super) const HALF_MD4_UNSIGNED: u8 = 4;
    /// The TEA hash of the bytes as unsigned numbers.
    pub(super) const TEA_UNSIGNED: u8 = 5;
}

/// The TEA transform of `buf` with the 4 words `input`.
fn tea_transform(buf: &mut [u32; 4], input: &[u32]) {
    const DELTA: u32 = 0x9e37_79b9;
    let mut sum = 0u32;
    let (mut b0, mut b1) = (buf[0], buf[1]);
    let (a, b, c, d) = (input[0], input[1], input[2], input[3]);
    for _ in 0..16 {
        sum = sum.wrapping_add(DELTA);
        b0 = b0.wrapping_add(
            (b1 << 4).wrapping_add(a) ^ b1.wrapping_add(sum) ^ (b1 >> 5).wrapping_add(b),
        );
        b1 = b1.wrapping_add(
            (b0 << 4).wrapping_add(c) ^ b0.wrapping_add(sum) ^ (b0 >> 5).wrapping_add(d),
        );
    }
    buf[0] = buf[0].wrapping_add(b0);
    buf[1] = buf[1].wrapping_add(b1);
}

/// The cut-down MD4 transform of `buf` with the 8 words `input`, `half_md4_transform`.
fn half_md4_transform(buf: &mut [u32; 4], input: &[u32]) {
    const K2: u32 = 0x5a82_7999;
    const K3: u32 = 0x6ed9_eba1;
    let f = |x: u32, y: u32, z: u32| z ^ (x & (y ^ z));
    let g = |x: u32, y: u32, z: u32| (x & y).wrapping_add((x ^ y) & z);
    let h = |x: u32, y: u32, z: u32| x ^ y ^ z;
    let mut s = *buf;
    // Each step changes the words a, d, c and b in turn, as the ROUND macros of Linux.
    let mut round =
        |fun: &dyn Fn(u32, u32, u32) -> u32, k: u32, words: [usize; 8], shifts: [u32; 4]| {
            for (step, &word) in words.iter().enumerate() {
                let t = [0, 3, 2, 1][step % 4];
                let v = fun(s[(t + 1) % 4], s[(t + 2) % 4], s[(t + 3) % 4]);
                s[t] = s[t].wrapping_add(v).wrapping_add(input[word].wrapping_add(k));
                s[t] = s[t].rotate_left(shifts[step % 4]);
            }
        };
    round(&f, 0, [0, 1, 2, 3, 4, 5, 6, 7], [3, 7, 11, 19]);
    round(&g, K2, [1, 3, 5, 7, 0, 2, 4, 6], [3, 5, 9, 13]);
    round(&h, K3, [3, 7, 2, 6, 1, 5, 0, 4], [3, 9, 11, 15]);
    for (word, add) in buf.iter_mut().zip(s) {
        *word = word.wrapping_add(add);
    }
}

/// The legacy hash of `name`, `dx_hack_hash`.
fn legacy_hash(name: &[u8], signed: bool) -> u32 {
    let (mut hash0, mut hash1) = (0x12a3_fe2d_u32, 0x37ab_e8f9_u32);
    for &c in name {
        let c = if signed { i32::from(c as i8) } else { i32::from(c) };
        let mut hash = hash1.wrapping_add(hash0 ^ c.wrapping_mul(7_152_373) as u32);
        if hash & 0x8000_0000 != 0 {
            hash = hash.wrapping_sub(0x7fff_ffff);
        }
        hash1 = hash0;
        hash0 = hash;
    }
    hash0 << 1
}

/// Puts the bytes of `msg` in `num` words, `str2hashbuf`. `len` is the length of the rest of the
/// name, for the padding.
fn str2hashbuf(msg: &[u8], len: usize, num: usize, signed: bool) -> [u32; 8] {
    let byte = |c: u8| if signed { i32::from(c as i8) as u32 } else { u32::from(c) };
    let mut pad = len as u32 | (len as u32) << 8;
    pad |= pad << 16;
    let len = len.min(num * 4);
    let mut out = [pad; 8];
    let (words, rest) = msg[..len].as_chunks::<4>();
    let mut i = 0;
    for w in words {
        out[i] = (byte(w[0]) << 24)
            .wrapping_add(byte(w[1]) << 16)
            .wrapping_add(byte(w[2]) << 8)
            .wrapping_add(byte(w[3]));
        i += 1;
    }
    if i < num {
        out[i] = rest.iter().fold(pad, |val, &c| byte(c).wrapping_add(val << 8));
    }
    out
}

/// The hash and the minor hash of `name` with the hash `version` and the seed `seed`, as
/// `ext4fs_dirhash`. Gives `None` for a version that the driver does not know.
pub(crate) fn dirhash(version: u8, seed: &[u32; 4], name: &[u8]) -> Option<(u32, u32)> {
    let mut buf = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];
    if seed.iter().any(|&w| w != 0) {
        buf = *seed;
    }
    let (hash, minor) = match version {
        version::LEGACY => (legacy_hash(name, true), 0),
        version::LEGACY_UNSIGNED => (legacy_hash(name, false), 0),
        version::HALF_MD4 | version::HALF_MD4_UNSIGNED => {
            let signed = version == version::HALF_MD4;
            for (i, chunk) in name.chunks(32).enumerate() {
                let input = str2hashbuf(chunk, name.len() - i * 32, 8, signed);
                half_md4_transform(&mut buf, &input);
            }
            (buf[1], buf[2])
        }
        version::TEA | version::TEA_UNSIGNED => {
            let signed = version == version::TEA;
            for (i, chunk) in name.chunks(16).enumerate() {
                let input = str2hashbuf(chunk, name.len() - i * 16, 4, signed);
                tea_transform(&mut buf, &input);
            }
            (buf[0], buf[1])
        }
        _ => return None,
    };
    let hash = hash & !1;
    let hash = if hash == EOF_32BIT << 1 { (EOF_32BIT - 1) << 1 } else { hash };
    Some((hash, minor))
}

/// The hash of the names of one directory.
#[derive(Clone, Copy)]
pub(crate) struct Hasher {
    /// The hash version, with the unsigned variant of the file system.
    version: u8,
    /// The seed of the file system.
    seed: [u32; 4],
}

impl Hasher {
    /// The hash of `name` in the index.
    fn hash(&self, name: &[u8]) -> u32 {
        dirhash(self.version, &self.seed, name).map_or(0, |(hash, _)| hash)
    }
}

/// A block of the index in memory, and the entry that a search went through.
struct Index {
    /// The block of the disk.
    block: u64,
    data: Vec<u8>,
    /// The offset of the count and the limit, which is the first entry.
    base: usize,
    /// The entry that the search went through.
    at: usize,
}

impl Index {
    /// The number of entries.
    fn count(&self) -> usize {
        usize::from(u16_at(&self.data, self.base + 2))
    }

    /// The largest number of entries.
    fn limit(&self) -> usize {
        usize::from(u16_at(&self.data, self.base))
    }

    fn set_count(&mut self, count: usize) {
        put16(&mut self.data, self.base + 2, count as u16);
    }

    /// The hash of the entry `i`. The entry 0 has no hash.
    fn hash(&self, i: usize) -> u32 {
        if i == 0 { 0 } else { u32_at(&self.data, self.base + 8 * i) }
    }

    /// The block that the entry `i` points to. The high 4 bits are for flags.
    fn child(&self, i: usize) -> u64 {
        u64::from(u32_at(&self.data, self.base + 8 * i + 4) & 0x0fff_ffff)
    }

    /// Adds the entry `(hash, child)` after the entry that the search went through, as
    /// `dx_insert_block`.
    fn insert(&mut self, hash: u32, child: u64) {
        let count = self.count();
        let at = self.base + 8 * (self.at + 1);
        self.data.copy_within(at..self.base + 8 * count, at + 8);
        put32(&mut self.data, at, hash);
        put32(&mut self.data, at + 4, child as u32);
        self.set_count(count + 1);
    }
}

/// The path that a search of the index went through, from the root to the lowest index block.
struct Probe {
    hasher: Hasher,
    /// The hash of the name.
    hash: u32,
    path: Vec<Index>,
}

impl Fs {
    /// Tells if the file system has `dir_index`.
    pub(crate) fn dir_index(&self) -> bool {
        self.sb.compat & layout::compat::DIR_INDEX != 0
    }

    /// Tells if the directory `raw` uses its htree index, as `is_dx`.
    pub(crate) fn is_dx(&self, raw: &RawInode) -> bool {
        self.dir_index() && raw.flags() & flags::INDEX != 0
    }

    /// The hash of the directories with the hash `version` of an index root. Gives `None` for
    /// a version that the driver does not know.
    fn hasher(&self, version: u8) -> Option<Hasher> {
        if version > version::TEA {
            return None;
        }
        let unsigned = self.sb.flags & layout::sb_flags::UNSIGNED_HASH != 0;
        Some(Hasher { version: version + if unsigned { 3 } else { 0 }, seed: self.sb.hash_seed })
    }

    /// The largest number of index levels, as `ext4_dir_htree_level`.
    fn htree_levels(&self) -> usize {
        if self.sb.incompat & layout::incompat::LARGEDIR != 0 { 3 } else { 2 }
    }

    /// The length of the `dx_tail` of an index block.
    fn dx_tail(&self) -> usize {
        if self.metadata_csum() { DX_TAIL } else { 0 }
    }

    /// The number of entries in the root, as `dx_root_limit`.
    fn root_limit(&self, info_len: usize) -> usize {
        (self.sb.block_size as usize - 12 - 12 - info_len - self.dx_tail()) / 8
    }

    /// The number of entries in a node block, as `dx_node_limit`.
    fn node_limit(&self) -> usize {
        (self.sb.block_size as usize - 8 - self.dx_tail()) / 8
    }

    /// Writes the checksum of the index block `data` of the directory `ino`, as
    /// `ext4_dx_csum_set`. The count and the limit are at `base`.
    fn dx_seal(&self, ino: u32, raw: &RawInode, data: &mut [u8], base: usize) {
        if !self.metadata_csum() {
            return;
        }
        let limit = usize::from(u16_at(data, base));
        let count = usize::from(u16_at(data, base + 2));
        let tail = base + 8 * limit;
        if tail + DX_TAIL > data.len() || count > limit {
            return;
        }
        put32(data, tail, 0);
        let csum = crc::crc32c(self.inode_seed(ino, raw), &data[..base + 8 * count]);
        let csum = crc::crc32c(csum, &data[tail..tail + 4]);
        put32(data, tail + 4, crc::crc32c(csum, &[0; 4]));
    }

    /// Writes the index block `index` of the directory `ino`, with its checksum.
    fn write_index(&self, ino: u32, raw: &RawInode, index: &mut Index) -> Result<()> {
        self.dx_seal(ino, raw, &mut index.data, index.base);
        self.write(index.block * self.sb.block_size, &index.data)
    }

    /// Reads the index block `lblock` of the directory `raw`.
    fn read_index(&self, raw: &RawInode, lblock: u64, base: usize) -> Result<Index> {
        let (block, data) = self.dir_block(raw, lblock)?;
        Ok(Index { block, data, base, at: 0 })
    }

    /// Finds the path from the root of the index to the leaf for `name`, as `dx_probe`. Gives
    /// `None` if the index is not valid or has a hash that the driver does not know.
    fn dx_probe(&self, raw: &RawInode, name: &[u8]) -> Result<Option<Probe>> {
        let bs = self.sb.block_size as usize;
        let mut index = self.read_index(raw, 0, 0)?;
        let info = &index.data[INFO..INFO + INFO_LEN];
        let (version, info_len, levels, root_flags) =
            (info[4], usize::from(info[5]), usize::from(info[6]), info[7]);
        let Some(hasher) = self.hasher(version) else { return Ok(None) };
        if root_flags & 1 != 0 || levels >= self.htree_levels() || INFO + info_len + 8 > bs {
            return Ok(None);
        }
        index.base = INFO + info_len;
        if index.limit() != self.root_limit(info_len) {
            return Ok(None);
        }
        let hash = hasher.hash(name);
        let mut path: Vec<Index> = Vec::new();
        let mut seen = vec![0];
        loop {
            let count = index.count();
            if count == 0 || count > index.limit() || index.base + 8 * count > bs {
                return Ok(None);
            }
            // The last entry with a hash that is not larger than the hash of the name.
            let (mut lo, mut hi) = (1, count);
            while lo < hi {
                let mid = lo + (hi - lo) / 2;
                if index.hash(mid) > hash { hi = mid } else { lo = mid + 1 }
            }
            index.at = lo - 1;
            let child = index.child(index.at);
            if seen.contains(&child) {
                return Ok(None);
            }
            path.push(index);
            if path.len() > levels {
                return Ok(Some(Probe { hasher, hash, path }));
            }
            seen.push(child);
            index = self.read_index(raw, child, 8)?;
            if index.limit() != self.node_limit() {
                return Ok(None);
            }
        }
    }

    /// Moves `path` to the next leaf if the next leaf can have names with the hash `hash`, as
    /// `ext4_htree_next_block`. Gives false at the end of the index, or if the next leaf starts
    /// with another hash.
    fn dx_next(&self, raw: &RawInode, path: &mut [Index], hash: u32) -> Result<bool> {
        let mut level = path.len();
        loop {
            if level == 0 {
                return Ok(false);
            }
            level -= 1;
            path[level].at += 1;
            if path[level].at < path[level].count() {
                break;
            }
        }
        let index = &path[level];
        if index.hash(index.at) & !1 != hash {
            return Ok(false);
        }
        for low in level + 1..path.len() {
            let child = path[low - 1].child(path[low - 1].at);
            path[low] = self.read_index(raw, child, 8)?;
        }
        Ok(true)
    }

    /// Finds the entry `name` in the indexed directory `raw`, as `ext4_dx_find_entry`. Gives
    /// `None` if the index is not valid, so that the caller reads all the blocks.
    pub(crate) fn dx_find(
        &self,
        raw: &RawInode,
        name: &[u8],
    ) -> Result<Option<Option<crate::dir::Slot>>> {
        let Some(Probe { hash, mut path, .. }) = self.dx_probe(raw, name)? else {
            return Ok(None);
        };
        loop {
            let Some(last) = path.last() else { return Ok(None) };
            let lblock = last.child(last.at);
            let (_, data) = self.dir_block(raw, lblock)?;
            if let Some(slot) = search_block(&data, lblock, name)? {
                return Ok(Some(Some(slot)));
            }
            if !self.dx_next(raw, &mut path, hash)? {
                return Ok(Some(None));
            }
        }
    }
}

impl Tx<'_> {
    /// Adds the block `data` at the end of the directory `ino`. Gives its block in the
    /// directory and its block on the disk.
    fn append_dir_block(
        &mut self,
        ino: u32,
        raw: &mut RawInode,
        data: &[u8],
    ) -> Result<(u64, u64)> {
        let size = raw.size();
        self.write_data(ino, raw, size, data)?;
        let lblock = size / self.fs.sb.block_size;
        let Some((block, _)) = self.fs.map(raw, lblock)? else { return Err(Errno::EIO) };
        Ok((lblock, block))
    }

    /// Adds the entry `name` to the indexed directory `dir`, as `ext4_dx_add_entry`. Gives false
    /// if the index is not valid, so that the caller adds the entry to the list. A full leaf
    /// splits. A full index block splits, or the index gets a new level, up to the limit.
    pub(crate) fn dx_add(
        &mut self,
        dir: &Node,
        raw: &mut RawInode,
        name: &[u8],
        ino: u32,
        kind: FileType,
    ) -> Result<bool> {
        let fs = self.fs;
        let bs = fs.sb.block_size;
        loop {
            let Some(Probe { hasher, hash, mut path }) = fs.dx_probe(raw, name)? else {
                return Ok(false);
            };
            let Some(last) = path.last_mut() else { return Ok(false) };
            let (block, mut data) = fs.dir_block(raw, last.child(last.at))?;
            if fs.put_in_block(&mut data, name, ino, kind)? {
                fs.seal(dir.ino, raw, &mut data);
                fs.write(block * bs, &data)?;
                return Ok(true);
            }
            if last.count() < last.limit() {
                self.split_leaf(
                    dir.ino,
                    raw,
                    hasher,
                    last,
                    (block, data),
                    hash,
                    (name, ino, kind),
                )?;
                return Ok(true);
            }
            // The index block is full. After it changes, a new search finds the path again.
            self.grow_index(dir.ino, raw, &mut path)?;
        }
    }

    /// Makes room in the full lowest index block of `path`. The first index block above it with
    /// room gets a new entry for a new block with half of the entries. If all the index blocks of
    /// the path are full, the root moves its entries to a new node block, and the index gets one
    /// more level. Gives `ENOSPC` if the index has the largest number of levels.
    fn grow_index(&mut self, ino: u32, raw: &mut RawInode, path: &mut [Index]) -> Result<()> {
        let fs = self.fs;
        let bs = fs.sb.block_size as usize;
        let mut level = path.len() - 1;
        while level > 0 && path[level - 1].count() >= path[level - 1].limit() {
            level -= 1;
        }
        let add_level = level == 0;
        if add_level && path.len() >= fs.htree_levels() {
            return Err(Errno::ENOSPC);
        }
        let mut node = vec![0u8; bs];
        put16(&mut node, 4, bs as u16);
        let index = &mut path[level];
        let (base, count) = (index.base, index.count());
        let new = raw.size() / bs as u64;
        if add_level {
            node[8..8 + 8 * count].copy_from_slice(&index.data[base..base + 8 * count]);
            put16(&mut node, 8, fs.node_limit() as u16);
            fs.dx_seal(ino, raw, &mut node, 8);
            self.append_dir_block(ino, raw, &node)?;
            index.set_count(1);
            put32(&mut index.data, base + 4, new as u32);
            index.data[INFO + 6] += 1;
            return fs.write_index(ino, raw, index);
        }
        let half = count / 2;
        let hash = index.hash(half);
        node[8..8 + 8 * (count - half)]
            .copy_from_slice(&index.data[base + 8 * half..base + 8 * count]);
        put16(&mut node, 8, fs.node_limit() as u16);
        put16(&mut node, 10, (count - half) as u16);
        fs.dx_seal(ino, raw, &mut node, 8);
        self.append_dir_block(ino, raw, &node)?;
        index.set_count(half);
        fs.write_index(ino, raw, index)?;
        let parent = &mut path[level - 1];
        parent.insert(hash, new);
        fs.write_index(ino, raw, parent)
    }

    /// Splits the full leaf `leaf`, as `do_split`. The names with the highest hashes move to a
    /// new block, so that each block has about half of the names, and `parent` gets an entry for
    /// the new block. Then the new entry goes to the block of its hash.
    #[allow(clippy::too_many_arguments)]
    fn split_leaf(
        &mut self,
        ino: u32,
        raw: &mut RawInode,
        hasher: Hasher,
        parent: &mut Index,
        leaf: (u64, Vec<u8>),
        hash: u32,
        entry: (&[u8], u32, FileType),
    ) -> Result<()> {
        let fs = self.fs;
        let bs = fs.sb.block_size as usize;
        let usable = bs - fs.tail();
        let (block, data) = leaf;
        // The hash, the offset and the length of the record of each entry, in hash order.
        let mut map: Vec<(u32, usize, usize)> = Vec::new();
        let mut at = 0;
        while at < usable {
            let rec = usize::from(u16_at(&data, at + 4));
            let name_len = usize::from(data[at + 6]);
            if rec < 8 || at + rec > usable || at + 8 + name_len > at + rec {
                return Err(Errno::EUCLEAN);
            }
            if u32_at(&data, at) != 0 && name_len != 0 {
                map.push((hasher.hash(&data[at + 8..at + 8 + name_len]), at, rec));
            }
            at += rec;
        }
        map.sort_by_key(|&(hash, ..)| hash);
        // No block gets more than half of the block.
        let count = map.len();
        let (mut size, mut moved) = (0, 0);
        for &(_, _, rec) in map.iter().rev() {
            if size + rec / 2 > bs / 2 {
                break;
            }
            size += rec;
            moved += 1;
        }
        let split = if moved < count { count - moved } else { count / 2 };
        if split == 0 {
            return Err(Errno::EUCLEAN);
        }
        let hash2 = map[split].0;
        let continued = u32::from(hash2 == map[split - 1].0);
        // The entries that stay keep their order in the block.
        let mut stay: Vec<usize> = map[..split].iter().map(|&(_, at, _)| at).collect();
        stay.sort_unstable();
        let pack = |offsets: &mut dyn Iterator<Item = usize>| {
            let mut out = vec![0u8; bs];
            let (mut to, mut last) = (0, 0);
            for at in offsets {
                let len = rec_len(usize::from(data[at + 6]));
                out[to..to + len].copy_from_slice(&data[at..at + len]);
                put16(&mut out, to + 4, len as u16);
                last = to;
                to += len;
            }
            put16(&mut out, last + 4, (usable - last) as u16);
            out
        };
        let mut low = pack(&mut stay.into_iter());
        let mut high = pack(&mut map[split..].iter().map(|&(_, at, _)| at));
        let (name, ino_new, kind) = entry;
        let target = if hash >= hash2 { &mut high } else { &mut low };
        if !fs.put_in_block(target, name, ino_new, kind)? {
            return Err(Errno::EUCLEAN);
        }
        fs.seal(ino, raw, &mut low);
        fs.seal(ino, raw, &mut high);
        let (new, _) = self.append_dir_block(ino, raw, &high)?;
        fs.write(block * bs as u64, &low)?;
        parent.insert(hash2 + continued, new);
        fs.write_index(ino, raw, parent)
    }

    /// Changes the full directory `dir` of one block into an indexed directory, and adds the
    /// entry `name`, as `make_indexed_dir`. The entries after `..` move to a new leaf, the
    /// block 0 becomes the root, and the leaf splits. Gives false if the file system has a
    /// default hash that the driver does not know, and the directory does not change.
    pub(crate) fn make_indexed(
        &mut self,
        dir: &Node,
        raw: &mut RawInode,
        root: (u64, Vec<u8>),
        entry: (&[u8], u32, FileType),
    ) -> Result<bool> {
        let fs = self.fs;
        let bs = fs.sb.block_size as usize;
        let usable = bs - fs.tail();
        let version = fs.sb.def_hash_version;
        let Some(hasher) = fs.hasher(version) else { return Ok(false) };
        let (block, mut data) = root;
        if u16_at(&data, 4) != 12
            || data[6] != 1
            || data[8] != b'.'
            || data[12 + 6] != 2
            || &data[12 + 8..12 + 10] != b".."
        {
            return Err(Errno::EUCLEAN);
        }
        let start = 12 + usize::from(u16_at(&data, 12 + 4));
        if start >= usable {
            return Err(Errno::EUCLEAN);
        }
        let mut leaf = vec![0u8; bs];
        leaf[..usable - start].copy_from_slice(&data[start..usable]);
        let mut at = 0;
        loop {
            let rec = usize::from(u16_at(&leaf, at + 4));
            if rec < 8 || at + rec > usable - start {
                return Err(Errno::EUCLEAN);
            }
            if at + rec == usable - start {
                put16(&mut leaf, at + 4, (usable - at) as u16);
                break;
            }
            at += rec;
        }
        fs.seal(dir.ino, raw, &mut leaf);
        let (lblock, leaf_block) = self.append_dir_block(dir.ino, raw, &leaf)?;
        // The root: `..` covers the rest of the block, then the information and one entry.
        data[INFO..].fill(0);
        put16(&mut data, 12 + 4, (bs - 12) as u16);
        data[INFO + 4] = version;
        data[INFO + 5] = INFO_LEN as u8;
        let base = INFO + INFO_LEN;
        put16(&mut data, base, fs.root_limit(INFO_LEN) as u16);
        put16(&mut data, base + 2, 1);
        put32(&mut data, base + 4, lblock as u32);
        let mut index = Index { block, data, base, at: 0 };
        fs.write_index(dir.ino, raw, &mut index)?;
        raw.set_flags(raw.flags() | flags::INDEX);
        let hash = hasher.hash(entry.0);
        self.split_leaf(dir.ino, raw, hasher, &mut index, (leaf_block, leaf), hash, entry)?;
        Ok(true)
    }
}
