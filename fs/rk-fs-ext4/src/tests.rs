//! Tests on a small ext4 image that the test makes byte by byte. The image has blocks of 1 KiB,
//! one group of 64 blocks and 32 inodes of 256 bytes.

use super::*;
use alloc::format;
use layout::flags;
use rk_frame::sync::SpinLock;
use rk_vfs::xattr::{XATTR_CREATE, XATTR_REPLACE};
use rk_vfs::{FileType, Inode, SetAttr, Timespec};

const BS: usize = 1024;
const INODE_TABLE: usize = 5;

/// A disk in memory, which the test can mount again.
#[derive(Clone)]
struct Ram(Arc<SpinLock<Vec<u8>>>);

impl Disk for Ram {
    fn read(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let at = offset as usize;
        let img = self.0.lock();
        let data = img.get(at..at + buf.len()).ok_or(Errno::EIO)?;
        buf.copy_from_slice(data);
        Ok(())
    }

    fn write(&self, offset: u64, buf: &[u8]) -> Result<()> {
        let at = offset as usize;
        let mut img = self.0.lock();
        img.get_mut(at..at + buf.len()).ok_or(Errno::EIO)?.copy_from_slice(buf);
        Ok(())
    }
}

impl Ram {
    fn u32_at(&self, at: usize) -> u32 {
        layout::u32_at(&self.0.lock(), at)
    }

    /// The free blocks and the free inodes in the superblock.
    fn free(&self) -> (u32, u32) {
        (self.u32_at(1024 + 0xc), self.u32_at(1024 + 0x10))
    }
}

struct Image(Vec<u8>);

impl Image {
    fn put16(&mut self, at: usize, v: u16) {
        self.0[at..at + 2].copy_from_slice(&v.to_le_bytes());
    }

    fn put32(&mut self, at: usize, v: u32) {
        self.0[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }

    /// Writes the inode `ino` with the mode, the size and the link count. Gives its offset.
    fn inode(&mut self, ino: usize, mode: u16, size: u32, links: u16, flags: u32) -> usize {
        let at = INODE_TABLE * BS + (ino - 1) * 256;
        self.put16(at, mode);
        self.put32(at + 0x4, size);
        self.put32(at + 0x10, 1_700_000_000);
        self.put16(at + 0x1a, links);
        self.put32(at + 0x20, flags);
        self.put16(at + 0x80, 32);
        self.put32(at + 0x88, 5 << 2);
        at
    }

    /// Writes an extent tree of depth 0 with the extents `(lblock, len, block)` in `i_block`.
    fn extents(&mut self, inode: usize, extents: &[(u32, u16, u32)]) {
        let at = inode + 0x28;
        self.put16(at, layout::EXTENT_MAGIC);
        self.put16(at + 2, extents.len() as u16);
        self.put16(at + 4, 4);
        for (i, &(lblock, len, block)) in extents.iter().enumerate() {
            let e = at + 12 + i * 12;
            self.put32(e, lblock);
            self.put16(e + 4, len);
            self.put32(e + 8, block);
        }
    }

    /// Writes the directory entries `(ino, type, name)` in the block `block`. The last entry
    /// takes the rest of the block.
    fn dir(&mut self, block: usize, entries: &[(u32, u8, &[u8])]) {
        let mut at = block * BS;
        for (i, &(ino, kind, name)) in entries.iter().enumerate() {
            let len = if i + 1 == entries.len() {
                (block + 1) * BS - at
            } else {
                (8 + name.len()).next_multiple_of(4)
            };
            self.put32(at, ino);
            self.put16(at + 4, len as u16);
            self.0[at + 6] = name.len() as u8;
            self.0[at + 7] = kind;
            self.0[at + 8..at + 8 + name.len()].copy_from_slice(name);
            at += len;
        }
    }
}

fn image() -> Vec<u8> {
    let mut img = Image(vec![0u8; 64 * BS]);
    let sb = 1024;
    img.put32(sb, 32);
    img.put32(sb + 0x4, 64);
    img.put32(sb + 0x14, 1);
    img.put32(sb + 0x18, 0);
    img.put32(sb + 0x20, 8192);
    img.put32(sb + 0x28, 32);
    img.put16(sb + 0x38, layout::MAGIC);
    img.put32(sb + 0x4c, 1);
    img.put32(sb + 0x54, 11);
    img.put16(sb + 0x58, 256);
    img.put32(sb + 0x60, layout::incompat::FILETYPE | layout::incompat::EXTENTS);
    // The group descriptor in the block 2.
    img.put32(2 * BS, 3);
    img.put32(2 * BS + 4, 4);
    img.put32(2 * BS + 8, INODE_TABLE as u32);
    // The used blocks: the superblock, the descriptors, the bitmaps, the inode table and the
    // data. The bit 0 is the block 1. The bits past the last block are set.
    let used: Vec<usize> = (1..=12).chain([20, 21, 22, 24, 25, 26, 30, 40]).collect();
    for &b in &used {
        img.0[3 * BS + (b - 1) / 8] |= 1 << ((b - 1) % 8);
    }
    img.0[3 * BS + 63 / 8] |= 0x80;
    img.0[3 * BS + 8..4 * BS].fill(0xff);
    for i in 0..15 {
        img.0[4 * BS + i / 8] |= 1 << (i % 8);
    }
    img.0[4 * BS + 4..5 * BS].fill(0xff);
    img.put32(sb + 0xc, 63 - used.len() as u32);
    img.put32(sb + 0x10, 32 - 15);
    img.put16(2 * BS + 0xc, 63 - used.len() as u16);
    img.put16(2 * BS + 0xe, 32 - 15);
    img.put16(2 * BS + 0x10, 2);

    let root = img.inode(2, 0o40755, BS as u32, 4, flags::EXTENTS);
    img.extents(root, &[(0, 1, 20)]);
    img.dir(
        20,
        &[(2, 2, b"."), (2, 2, b".."), (0, 0, b"gone"), (11, 1, b"hello"), (12, 2, b"sub")],
    );

    // A file of 3 blocks with a hole in the block 1.
    let hello = img.inode(11, 0o100644, 3000, 1, flags::EXTENTS);
    img.extents(hello, &[(0, 1, 22), (2, 1, 24)]);
    img.0[22 * BS..23 * BS].fill(b'a');
    img.0[24 * BS..25 * BS].fill(b'c');

    let sub = img.inode(12, 0o40700, BS as u32, 2, flags::EXTENTS);
    img.extents(sub, &[(0, 1, 21)]);
    img.dir(
        21,
        &[(12, 2, b"."), (2, 2, b".."), (13, 7, b"link"), (14, 1, b"old"), (15, 7, b"long")],
    );

    // A short symbolic link in `i_block`.
    let link = img.inode(13, 0o120777, 8, 1, 0);
    img.0[link + 0x28..link + 0x30].copy_from_slice(b"../hello");

    // A file with a block map: the block 0 is direct, and the block 12 is in the indirect block.
    let old = img.inode(14, 0o100600, 13 * BS as u32, 1, 0);
    img.put32(old + 0x28, 25);
    img.put32(old + 0x28 + 12 * 4, 40);
    img.put32(40 * BS, 26);
    img.0[25 * BS] = 1;
    img.0[26 * BS + BS - 1] = 2;

    // A long symbolic link in a block.
    let long = img.inode(15, 0o120777, 100, 1, flags::EXTENTS);
    img.extents(long, &[(0, 1, 30)]);
    img.0[30 * BS..30 * BS + 100].fill(b'x');
    img.0
}

fn open(img: Vec<u8>) -> Result<Arc<Fs>> {
    Fs::open(7, alloc::boxed::Box::new(Ram(Arc::new(SpinLock::new(img)))), true)
}

fn open_rw() -> (Arc<Fs>, Ram) {
    let ram = Ram(Arc::new(SpinLock::new(image())));
    (Fs::open(7, alloc::boxed::Box::new(ram.clone()), false).unwrap(), ram)
}

/// Mounts the disk again, to read what the disk has and not what memory has.
fn again(ram: &Ram) -> Arc<Fs> {
    Fs::open(7, alloc::boxed::Box::new(ram.clone()), true).unwrap()
}

fn read_all(inode: &dyn Inode) -> Vec<u8> {
    let mut buf = vec![0u8; inode.metadata().size as usize];
    assert_eq!(inode.read_at(0, &mut buf).unwrap(), buf.len());
    buf
}

fn names(dir: &dyn Inode) -> Vec<(Vec<u8>, FileType)> {
    let mut out = Vec::new();
    let mut pos = 0;
    while let Some((e, next)) = dir.read_dir(pos).unwrap() {
        out.push((e.name, e.kind));
        pos = next;
    }
    out
}

#[test]
fn the_root_lists_its_entries() {
    let fs = open(image()).unwrap();
    let root = fs.root().unwrap();
    let meta = root.metadata();
    assert_eq!((meta.ino, meta.dev, meta.nlink), (2, 7, 4));
    assert!(meta.is_dir());
    assert_eq!(meta.mtime, Timespec { sec: 1_700_000_000, nsec: 5 });
    assert_eq!(
        names(&*root),
        [
            (b".".to_vec(), FileType::Directory),
            (b"..".to_vec(), FileType::Directory),
            (b"hello".to_vec(), FileType::Regular),
            (b"sub".to_vec(), FileType::Directory),
        ]
    );
    assert_eq!(root.lookup(b"gone").err(), Some(Errno::ENOENT));
}

#[test]
fn a_file_reads_its_extents_and_holes() {
    let fs = open(image()).unwrap();
    let hello = fs.root().unwrap().lookup(b"hello").unwrap();
    let mut buf = vec![9u8; 4000];
    assert_eq!(hello.read_at(0, &mut buf).unwrap(), 3000);
    assert!(buf[..BS].iter().all(|&b| b == b'a'));
    assert!(buf[BS..2 * BS].iter().all(|&b| b == 0));
    assert!(buf[2 * BS..3000].iter().all(|&b| b == b'c'));
    assert_eq!(hello.read_at(3000, &mut buf).unwrap(), 0);
    // Two lookups give one inode.
    let again = fs.root().unwrap().lookup(b"hello").unwrap();
    assert!(Arc::ptr_eq(&hello, &again));
}

#[test]
fn a_file_reads_its_block_map() {
    let fs = open(image()).unwrap();
    let old = fs.root().unwrap().lookup(b"sub").unwrap().lookup(b"old").unwrap();
    let mut buf = vec![0u8; 13 * BS];
    assert_eq!(old.read_at(0, &mut buf).unwrap(), 13 * BS);
    assert_eq!(buf[0], 1);
    assert_eq!(buf[13 * BS - 1], 2);
    assert_eq!(buf.iter().map(|&b| u32::from(b)).sum::<u32>(), 3);
}

#[test]
fn symbolic_links_give_their_targets() {
    let fs = open(image()).unwrap();
    let sub = fs.root().unwrap().lookup(b"sub").unwrap();
    assert_eq!(sub.lookup(b"link").unwrap().read_link().unwrap(), b"../hello");
    assert_eq!(sub.lookup(b"long").unwrap().read_link().unwrap(), vec![b'x'; 100]);
}

#[test]
fn a_change_gives_erofs() {
    let fs = open(image()).unwrap();
    let root = fs.root().unwrap();
    assert_eq!(root.create(b"new", FileType::Regular, 0o644, 0).err(), Some(Errno::EROFS));
    assert_eq!(root.unlink(b"hello"), Err(Errno::EROFS));
    let hello = root.lookup(b"hello").unwrap();
    assert_eq!(hello.write_at(0, b"x"), Err(Errno::EROFS));
    assert_eq!(hello.lookup(b"x").err(), Some(Errno::ENOTDIR));
}

#[test]
fn a_bad_superblock_does_not_mount() {
    let mut img = image();
    img[1024 + 0x38] = 0;
    assert_eq!(open(img).err(), Some(Errno::EINVAL));
    let mut img = image();
    img[1024 + 0x62] = 0x01;
    assert_eq!(open(img).err(), Some(Errno::EOPNOTSUPP));
    // A block size of 8192 is larger than the page size.
    let mut img = image();
    img[1024 + 0x18] = 3;
    assert_eq!(open(img).err(), Some(Errno::EINVAL));
}

#[test]
fn a_new_file_keeps_its_data() {
    let (fs, ram) = open_rw();
    let free = ram.free();
    let root = fs.root().unwrap();
    let file = root.create(b"new", FileType::Regular, 0o640, 0).unwrap();
    let data: Vec<u8> = (0..5000u32).map(|i| i as u8).collect();
    assert_eq!(file.write_at(0, &data).unwrap(), 5000);
    assert_eq!(file.write_at(5000, b"end").unwrap(), 3);
    assert_eq!(ram.free(), (free.0 - 5, free.1 - 1));
    assert_eq!(root.create(b"new", FileType::Regular, 0o640, 0).err(), Some(Errno::EEXIST));
    drop((file, root, fs));

    let fs = again(&ram);
    let file = fs.root().unwrap().lookup(b"new").unwrap();
    let meta = file.metadata();
    assert_eq!((meta.size, meta.mode, meta.nlink, meta.blocks), (5003, 0o100640, 1, 10));
    let back = read_all(&*file);
    assert_eq!(&back[..5000], &data[..]);
    assert_eq!(&back[5000..], b"end");
}

#[test]
fn a_write_fills_a_hole_and_the_size_changes() {
    let (fs, ram) = open_rw();
    let root = fs.root().unwrap();
    let hello = root.lookup(b"hello").unwrap();
    hello.write_at(BS as u64 + 10, b"bb").unwrap();
    let file = root.create(b"t", FileType::Regular, 0o600, 0).unwrap();
    file.write_at(0, &vec![b'z'; 3 * BS]).unwrap();
    file.set_attr(&SetAttr { size: Some(1500), ..SetAttr::default() }).unwrap();
    file.set_attr(&SetAttr { size: Some(2 * BS as u64 + 1), ..SetAttr::default() }).unwrap();
    drop((hello, file, root, fs));

    let fs = again(&ram);
    let root = fs.root().unwrap();
    let back = read_all(&*root.lookup(b"hello").unwrap());
    assert!(back[BS..BS + 10].iter().all(|&b| b == 0));
    assert_eq!(&back[BS + 10..BS + 12], b"bb");
    assert_eq!(back[2 * BS], b'c');
    let back = read_all(&*root.lookup(b"t").unwrap());
    assert_eq!(back.len(), 2 * BS + 1);
    assert!(back[..1500].iter().all(|&b| b == b'z'));
    assert!(back[1500..].iter().all(|&b| b == 0));
}

#[test]
fn fallocate_gives_and_frees_blocks() {
    use rk_vfs::inode::falloc::{KEEP_SIZE, PUNCH_HOLE, ZERO_RANGE};
    let (fs, ram) = open_rw();
    let free = ram.free();
    let root = fs.root().unwrap();
    let file = root.create(b"f", FileType::Regular, 0o644, 0).unwrap();
    // New blocks read as zeros, and the size grows only without KEEP_SIZE.
    file.fallocate(0, 0, 2 * BS as u64).unwrap();
    assert_eq!(file.metadata().size, 2 * BS as u64);
    assert_eq!(ram.free().0, free.0 - 2);
    file.fallocate(KEEP_SIZE, 2 * BS as u64, BS as u64).unwrap();
    assert_eq!((file.metadata().size, ram.free().0), (2 * BS as u64, free.0 - 3));
    assert!(read_all(&*file).iter().all(|&b| b == 0));
    // A write into a new block keeps the zeros around it.
    file.write_at(10, b"ab").unwrap();
    file.write_at(BS as u64, &vec![b'x'; 2 * BS]).unwrap();
    assert_eq!(ram.free().0, free.0 - 3);
    // A hole frees the full block, and the parts at its ends become zeros.
    file.fallocate(PUNCH_HOLE | KEEP_SIZE, BS as u64 - 1, BS as u64 + 2).unwrap();
    assert_eq!(ram.free().0, free.0 - 2);
    file.fallocate(ZERO_RANGE, 2 * BS as u64 + 5, 5).unwrap();
    assert_eq!(file.fallocate(0x40, 0, 1), Err(Errno::EOPNOTSUPP));
    drop((file, root, fs));

    let fs = again(&ram);
    let back = read_all(&*fs.root().unwrap().lookup(b"f").unwrap());
    assert_eq!(back.len(), 3 * BS);
    assert_eq!(&back[10..12], b"ab");
    assert!(back[12..2 * BS + 1].iter().all(|&b| b == 0));
    assert!(back[2 * BS + 1..2 * BS + 5].iter().all(|&b| b == b'x'));
    assert!(back[2 * BS + 5..2 * BS + 10].iter().all(|&b| b == 0));
    assert!(back[2 * BS + 10..].iter().all(|&b| b == b'x'));
}

#[test]
fn fiemap_gives_the_extents() {
    use rk_vfs::inode::falloc::KEEP_SIZE;
    let (fs, ram) = open_rw();
    let file = fs.root().unwrap().create(b"f", FileType::Regular, 0o644, 0).unwrap();
    file.write_at(0, &vec![1u8; 2 * BS]).unwrap();
    file.fallocate(KEEP_SIZE, 4 * BS as u64, BS as u64).unwrap();
    let all = file.fiemap(0, u64::MAX).unwrap();
    assert_eq!(all.len(), 2);
    assert_eq!((all[0].logical, all[0].length, all[0].unwritten), (0, 2 * BS as u64, false));
    assert_eq!((all[1].logical, all[1].length, all[1].unwritten), (4 * BS as u64, BS as u64, true));
    assert!(all.iter().all(|e| e.physical != 0 && e.physical % BS as u64 == 0));
    // The first extent starts at the block of `start`.
    let part = file.fiemap(BS as u64 + 1, 1).unwrap();
    assert_eq!(part.len(), 1);
    assert_eq!((part[0].logical, part[0].length), (BS as u64, BS as u64));
    assert_eq!(part[0].physical, all[0].physical + BS as u64);
    assert!(file.fiemap(2 * BS as u64, 2 * BS as u64).unwrap().is_empty());
    // A truncate to the same size frees the blocks past the end of the file.
    let free = ram.free().0;
    file.set_attr(&SetAttr { size: Some(2 * BS as u64), ..SetAttr::default() }).unwrap();
    assert_eq!(ram.free().0, free + 1);
    assert_eq!(file.fiemap(0, u64::MAX).unwrap().len(), 1);
}

#[test]
fn the_inode_flags_are_kept() {
    use rk_vfs::inode::iflags::{APPEND, IMMUTABLE, NODUMP};
    let (fs, ram) = open_rw();
    let file = fs.root().unwrap().create(b"f", FileType::Regular, 0o644, 0).unwrap();
    let extents = 0x8_0000;
    assert_eq!(file.attr_flags(), Ok(extents));
    file.set_attr_flags(extents | IMMUTABLE | APPEND | NODUMP).unwrap();
    let file = again(&ram).root().unwrap().lookup(b"f").unwrap();
    assert_eq!(file.attr_flags(), Ok(extents | IMMUTABLE | APPEND | NODUMP));
}

#[test]
fn the_extent_flag_moves_the_file() {
    let extents = 0x8_0000;
    let (fs, ram) = open_rw();
    let root = fs.root().unwrap();
    // A file with one extent in the direct blocks moves to a block map.
    let file = root.create(b"f", FileType::Regular, 0o644, 0).unwrap();
    file.write_at(BS as u64, &vec![b'b'; 2 * BS]).unwrap();
    file.set_attr_flags(0).unwrap();
    assert_eq!(file.attr_flags(), Ok(0));
    assert_eq!(read_all(&*again(&ram).root().unwrap().lookup(b"f").unwrap())[BS], b'b');
    // The block map moves back to an extent tree, and the file can grow again.
    file.set_attr_flags(extents).unwrap();
    file.write_at(20 * BS as u64, b"end").unwrap();
    let back = again(&ram).root().unwrap().lookup(b"f").unwrap();
    assert_eq!(back.attr_flags(), Ok(extents));
    assert_eq!(back.fiemap(0, u64::MAX).unwrap().len(), 2);
    // A file with two extents, or past the direct blocks, does not move.
    let two = root.create(b"two", FileType::Regular, 0o644, 0).unwrap();
    two.write_at(0, b"a").unwrap();
    two.write_at(4 * BS as u64, b"b").unwrap();
    assert_eq!(two.set_attr_flags(0), Err(Errno::EOPNOTSUPP));
    let far = root.create(b"far", FileType::Regular, 0o644, 0).unwrap();
    far.write_at(12 * BS as u64, b"a").unwrap();
    assert_eq!(far.set_attr_flags(0), Err(Errno::EOPNOTSUPP));
    // The old file with an indirect block moves to an extent tree, and frees the indirect block.
    let free = ram.free().0;
    let old = root.lookup(b"sub").unwrap().lookup(b"old").unwrap();
    old.set_attr_flags(extents).unwrap();
    assert_eq!(ram.free().0, free + 1);
    let old = again(&ram).root().unwrap().lookup(b"sub").unwrap().lookup(b"old").unwrap();
    let data = read_all(&*old);
    assert_eq!((data[0], data[13 * BS - 1]), (1, 2));
    assert_eq!(old.fiemap(0, u64::MAX).unwrap().len(), 2);
}

#[test]
fn minixdf_counts_all_the_blocks() {
    let (fs, _ram) = open_rw();
    assert!(fs.stat().blocks < 64);
    fs.minix_df.store(true, core::sync::atomic::Ordering::Relaxed);
    assert_eq!(fs.stat().blocks, 64);
}

#[test]
fn collapse_and_insert_move_the_blocks() {
    use rk_vfs::inode::falloc::{COLLAPSE_RANGE, INSERT_RANGE};
    let (fs, ram) = open_rw();
    let file = fs.root().unwrap().create(b"f", FileType::Regular, 0o644, 0).unwrap();
    for (i, c) in b"abcd".iter().enumerate() {
        file.write_at((i * BS) as u64, &vec![*c; BS]).unwrap();
    }
    let (b, free) = (BS as u64, ram.free().0);
    assert_eq!(file.fallocate(COLLAPSE_RANGE, 1, b), Err(Errno::EINVAL));
    assert_eq!(file.fallocate(COLLAPSE_RANGE, 2 * b, 2 * b), Err(Errno::EINVAL));
    assert_eq!(file.fallocate(INSERT_RANGE, 4 * b, b), Err(Errno::EINVAL));
    // A collapse of the second block frees it, and the blocks after it move down.
    file.fallocate(COLLAPSE_RANGE, b, b).unwrap();
    assert_eq!((file.metadata().size, ram.free().0), (3 * b, free + 1));
    // An insert before the second block leaves a hole of one block.
    file.fallocate(INSERT_RANGE, b, b).unwrap();
    assert_eq!((file.metadata().size, ram.free().0), (4 * b, free + 1));
    // An insert and a collapse at the same place give one extent again, as generic/064 checks.
    let (fs2, _) = open_rw();
    let g = fs2.root().unwrap().create(b"g", FileType::Regular, 0o644, 0).unwrap();
    g.write_at(0, &vec![1u8; 2 * BS]).unwrap();
    assert_eq!(g.fiemap(0, u64::MAX).unwrap().len(), 1);
    g.fallocate(INSERT_RANGE, BS as u64, BS as u64).unwrap();
    assert_eq!(g.fiemap(0, u64::MAX).unwrap().len(), 2);
    g.fallocate(COLLAPSE_RANGE, BS as u64, BS as u64).unwrap();
    assert_eq!(g.fiemap(0, u64::MAX).unwrap().len(), 1);
    drop((g, fs2, file, fs));

    let fs = again(&ram);
    let back = read_all(&*fs.root().unwrap().lookup(b"f").unwrap());
    assert_eq!(back.len(), 4 * BS);
    let firsts: Vec<u8> = back.chunks(BS).map(|c| c[0]).collect();
    assert_eq!(firsts, [b'a', 0, b'c', b'd']);
    assert!(back.chunks(BS).all(|c| c.iter().all(|&x| x == c[0])));
}

#[test]
fn unlink_frees_the_blocks_and_the_inode() {
    let (fs, ram) = open_rw();
    let free = ram.free();
    let root = fs.root().unwrap();
    let file = root.create(b"f", FileType::Regular, 0o644, 0).unwrap();
    file.write_at(0, &vec![1u8; 4 * BS]).unwrap();
    root.unlink(b"f").unwrap();
    // The open file keeps its blocks.
    assert_ne!(ram.free(), free);
    assert_eq!(read_all(&*file).len(), 4 * BS);
    drop(file);
    assert_eq!(ram.free(), free);
    root.unlink(b"hello").unwrap();
    assert_eq!(ram.free(), (free.0 + 2, free.1 + 1));
    assert_eq!(root.lookup(b"hello").err(), Some(Errno::ENOENT));
    assert_eq!(root.unlink(b"sub"), Err(Errno::EISDIR));
}

#[test]
fn directories_nest_and_count_their_links() {
    let (fs, ram) = open_rw();
    let free = ram.free();
    let root = fs.root().unwrap();
    let a = root.create(b"a", FileType::Directory, 0o755, 0).unwrap();
    let b = a.create(b"b", FileType::Directory, 0o755, 0).unwrap();
    b.create(b"c", FileType::Regular, 0o644, 0).unwrap();
    assert_eq!((root.metadata().nlink, a.metadata().nlink, b.metadata().nlink), (5, 3, 2));
    assert_eq!(a.rmdir(b"b"), Err(Errno::ENOTEMPTY));
    b.unlink(b"c").unwrap();
    a.rmdir(b"b").unwrap();
    assert_eq!(a.metadata().nlink, 2);
    drop(b);
    root.rmdir(b"a").unwrap();
    drop(a);
    assert_eq!(root.metadata().nlink, 4);
    assert_eq!(ram.free(), free);
}

#[test]
fn rename_moves_files_and_directories() {
    let (fs, ram) = open_rw();
    let root = fs.root().unwrap();
    let sub = root.lookup(b"sub").unwrap();
    let dir = root.create(b"d", FileType::Directory, 0o755, 0).unwrap();
    root.rename(b"hello", &sub, b"moved").unwrap();
    sub.rename(b"old", &sub, b"link").unwrap();
    root.rename(b"d", &sub, b"d2").unwrap();
    assert_eq!((root.metadata().nlink, sub.metadata().nlink), (4, 3));
    let new = sub.create(b"x", FileType::Regular, 0o644, 0).unwrap();
    new.write_at(0, b"new").unwrap();
    sub.rename(b"x", &sub, b"moved").unwrap();
    drop((new, dir, sub, root, fs));

    let fs = again(&ram);
    let root = fs.root().unwrap();
    assert_eq!(root.lookup(b"hello").err(), Some(Errno::ENOENT));
    let sub = root.lookup(b"sub").unwrap();
    assert_eq!(read_all(&*sub.lookup(b"moved").unwrap()), b"new");
    assert_eq!(sub.lookup(b"link").unwrap().metadata().size, 13 * BS as u64);
    let d2 = sub.lookup(b"d2").unwrap();
    assert!(Arc::ptr_eq(&d2.lookup(b"..").unwrap(), &sub));
}

#[test]
fn links_and_symbolic_links_are_made() {
    let (fs, ram) = open_rw();
    let root = fs.root().unwrap();
    let hello = root.lookup(b"hello").unwrap();
    root.link(b"same", &hello).unwrap();
    assert_eq!(hello.metadata().nlink, 2);
    assert_eq!(root.link(b"dir", &root.lookup(b"sub").unwrap()), Err(Errno::EPERM));
    root.symlink(b"short", b"hello").unwrap();
    root.symlink(b"long", &[b'y'; 200]).unwrap();
    drop((hello, root, fs));

    let fs = again(&ram);
    let root = fs.root().unwrap();
    assert!(Arc::ptr_eq(&root.lookup(b"same").unwrap(), &root.lookup(b"hello").unwrap()));
    assert_eq!(root.lookup(b"short").unwrap().read_link().unwrap(), b"hello");
    assert_eq!(root.lookup(b"long").unwrap().read_link().unwrap(), vec![b'y'; 200]);
}

#[test]
fn many_entries_and_extents_grow_the_trees() {
    let (fs, ram) = open_rw();
    let free = ram.free();
    let root = fs.root().unwrap();
    for i in 0..15 {
        root.create(format!("entry-{i:0>54}").as_bytes(), FileType::Regular, 0o644, 0).unwrap();
    }
    assert!(root.metadata().size > BS as u64);
    // Every second block makes one extent, so the tree has more than 4 extents.
    let file = root.create(b"sparse", FileType::Regular, 0o644, 0).unwrap();
    for i in 0..8u64 {
        file.write_at(i * 2 * BS as u64, &[i as u8 + 1]).unwrap();
    }
    // i_blocks counts the 8 data blocks and the one block of the tree, one time each.
    assert_eq!(file.metadata().blocks, 9 * (BS as u64 / 512));
    drop((file, root, fs));

    let fs = again(&ram);
    let root = fs.root().unwrap();
    assert_eq!(names(&*root).len(), 4 + 15 + 1);
    let back = read_all(&*root.lookup(b"sparse").unwrap());
    for i in 0..8 {
        assert_eq!(back[i * 2 * BS], i as u8 + 1);
    }
    drop((root, fs));

    let fs = Fs::open(7, alloc::boxed::Box::new(ram.clone()), false).unwrap();
    let root = fs.root().unwrap();
    root.unlink(b"sparse").unwrap();
    for i in 0..15 {
        root.unlink(format!("entry-{i:0>54}").as_bytes()).unwrap();
    }
    // The directory keeps its new block.
    assert_eq!(ram.free(), (free.0 - 1, free.1));
}

#[test]
fn a_block_map_file_grows_and_shrinks() {
    let (fs, ram) = open_rw();
    let free = ram.free().0;
    let old = fs.root().unwrap().lookup(b"sub").unwrap().lookup(b"old").unwrap();
    old.write_at(5, b"in").unwrap();
    // A hole in the direct blocks takes one block.
    old.write_at(2 * BS as u64, b"hole").unwrap();
    assert_eq!(ram.free().0, free - 1);
    // The block 300 is under the double indirect block, so it also takes two indirect blocks.
    old.write_at(300 * BS as u64 + 7, b"far").unwrap();
    assert_eq!(ram.free().0, free - 4);
    assert_eq!(old.metadata().size, 300 * BS as u64 + 10);
    drop((old, fs));
    let old = again(&ram).root().unwrap().lookup(b"sub").unwrap().lookup(b"old").unwrap();
    let data = read_all(&*old);
    assert_eq!(&data[5..7], b"in");
    assert_eq!(&data[2 * BS..2 * BS + 4], b"hole");
    assert_eq!(&data[300 * BS + 7..], b"far");
    assert_eq!(data[13 * BS - 1], 2);
    assert!(data[13 * BS..300 * BS].iter().all(|&b| b == 0));
    drop(old);
    // A truncate to one block frees all the blocks but the first, and the indirect blocks.
    let fs = Fs::open(7, alloc::boxed::Box::new(ram.clone()), false).unwrap();
    let old = fs.root().unwrap().lookup(b"sub").unwrap().lookup(b"old").unwrap();
    old.set_attr(&SetAttr { size: Some(BS as u64), ..SetAttr::default() }).unwrap();
    assert_eq!(ram.free().0, free + 2);
    assert_eq!(old.fiemap(0, u64::MAX).unwrap().len(), 1);
}

#[test]
fn a_disk_without_extents_keeps_new_files_in_a_block_map() {
    let mut img = image();
    img[1024 + 0x60] &= !(layout::incompat::EXTENTS as u8);
    let ram = Ram(Arc::new(SpinLock::new(img)));
    let fs = Fs::open(7, alloc::boxed::Box::new(ram.clone()), false).unwrap();
    let root = fs.root().unwrap();
    let file = root.create(b"new", FileType::Regular, 0o644, 0).unwrap();
    let data: Vec<u8> = (0..14 * BS).map(|i| (i % 251) as u8).collect();
    file.write_at(0, &data).unwrap();
    assert_eq!(file.attr_flags().unwrap() & flags::EXTENTS, 0);
    // 14 data blocks and the indirect block for the blocks 12 and 13.
    assert_eq!(file.metadata().blocks, (15 * BS / 512) as u64);
    assert_eq!(file.set_attr_flags(flags::EXTENTS), Err(Errno::EINVAL));
    drop((file, root, fs));
    let file = again(&ram).root().unwrap().lookup(b"new").unwrap();
    assert_eq!(read_all(&*file), data);
}

mod log {
    use super::*;
    use crate::journal::{MAGIC, be32, feature, jsb, put_be32};

    /// The journal has 16 blocks from the block 44 of the disk.
    const AT: usize = 44;
    const UUID: [u8; 16] = *b"0123456789abcdef";

    fn seed() -> u32 {
        crc::crc32c(!0, &UUID)
    }

    fn header(kind: u32, seq: u32) -> Vec<u8> {
        let mut b = vec![0u8; BS];
        put_be32(&mut b, 0, MAGIC);
        put_be32(&mut b, 4, kind);
        put_be32(&mut b, 8, seq);
        b
    }

    fn seal(b: &mut [u8], at: usize, seed: u32) {
        put_be32(b, at, 0);
        let csum = crc::crc32c(seed, b);
        put_be32(b, at, csum);
    }

    /// A descriptor block with a tag for each `(block, flags, data)`.
    fn descriptor(seq: u32, tags: &[(u32, u32, &[u8])]) -> Vec<u8> {
        let mut b = header(1, seq);
        let mut at = 12;
        for (i, &(block, flags, data)) in tags.iter().enumerate() {
            let mut flags = flags | if i == 0 { 0 } else { 2 };
            if i + 1 == tags.len() {
                flags |= 8;
            }
            put_be32(&mut b, at, block);
            put_be32(&mut b, at + 4, flags);
            let csum = crc::crc32c(crc::crc32c(seed(), &seq.to_be_bytes()), data);
            put_be32(&mut b, at + 12, csum);
            at += 16;
            if i == 0 {
                b[at..at + 16].copy_from_slice(&UUID);
                at += 16;
            }
        }
        seal(&mut b, BS - 4, seed());
        b
    }

    fn commit(seq: u32) -> Vec<u8> {
        let mut b = header(2, seq);
        seal(&mut b, 16, seed());
        b
    }

    fn revoke(seq: u32, blocks: &[u32]) -> Vec<u8> {
        let mut b = header(5, seq);
        put_be32(&mut b, 12, 16 + 4 * blocks.len() as u32);
        for (i, &block) in blocks.iter().enumerate() {
            put_be32(&mut b, 16 + 4 * i, block);
        }
        seal(&mut b, BS - 4, seed());
        b
    }

    /// The image with the journal inode 8, the log blocks `log` from the block 1 of the journal,
    /// and `RECOVER`.
    fn image_with(log: &[Vec<u8>]) -> Vec<u8> {
        let mut img = Image(image());
        let inode = img.inode(8, 0o100600, 16 * BS as u32, 1, flags::EXTENTS);
        img.extents(inode, &[(0, 16, AT as u32)]);
        img.put32(1024 + 0xe0, 8);
        img.put32(1024 + 0x5c, layout::compat::HAS_JOURNAL);
        img.put32(
            1024 + 0x60,
            layout::incompat::FILETYPE | layout::incompat::EXTENTS | layout::incompat::RECOVER,
        );
        let mut sb = header(4, 0);
        put_be32(&mut sb, jsb::BLOCK_SIZE, BS as u32);
        put_be32(&mut sb, jsb::MAX_LEN, 16);
        put_be32(&mut sb, jsb::FIRST, 1);
        put_be32(&mut sb, jsb::SEQUENCE, 5);
        put_be32(&mut sb, jsb::START, 1);
        put_be32(&mut sb, jsb::INCOMPAT, feature::REVOKE | feature::CSUM_V3);
        sb[jsb::UUID..jsb::UUID + 16].copy_from_slice(&UUID);
        seal(&mut sb, jsb::CHECKSUM, !0);
        img.0[AT * BS..(AT + 1) * BS].copy_from_slice(&sb);
        for (i, b) in log.iter().enumerate() {
            img.0[(AT + 1 + i) * BS..(AT + 2 + i) * BS].copy_from_slice(b);
        }
        img.0
    }

    #[test]
    fn the_replay_writes_the_committed_blocks() {
        let new = vec![b'n'; BS];
        let mut magic = vec![b'm'; BS];
        let mut escaped = magic.clone();
        put_be32(&mut magic, 0, MAGIC);
        escaped[..4].fill(0);
        let log = [
            descriptor(5, &[(22, 0, &new), (24, 0, &new)]),
            new.clone(),
            new.clone(),
            commit(5),
            revoke(6, &[24]),
            descriptor(6, &[(30, 1, &escaped)]),
            escaped.clone(),
            commit(6),
            // A transaction without a commit block.
            descriptor(7, &[(25, 0, &new)]),
            new.clone(),
        ];
        let ram = Ram(Arc::new(SpinLock::new(image_with(&log))));
        let fs = Fs::open(7, alloc::boxed::Box::new(ram.clone()), true).unwrap();
        let disk = ram.0.lock();
        assert_eq!(&disk[22 * BS..23 * BS], &new[..]);
        assert!(disk[24 * BS..25 * BS].iter().all(|&b| b == b'c'));
        assert_eq!(&disk[30 * BS..31 * BS], &magic[..]);
        assert_eq!(disk[25 * BS], 1);
        assert_eq!(layout::u32_at(&disk, 1024 + 0x60) & layout::incompat::RECOVER, 0);
        assert_eq!(be32(&disk, AT * BS + jsb::START), 0);
        assert_eq!(be32(&disk, AT * BS + jsb::SEQUENCE), 8);
        drop(disk);
        assert_eq!(fs.superblock().incompat & layout::incompat::RECOVER, 0);
        let mut buf = [0u8; 4];
        fs.root().unwrap().lookup(b"hello").unwrap().read_at(0, &mut buf).unwrap();
        assert_eq!(&buf, b"nnnn");
    }

    #[test]
    fn a_bad_commit_ends_the_log() {
        let new = vec![b'n'; BS];
        let mut bad = commit(5);
        bad[100] = 1;
        let log = [descriptor(5, &[(22, 0, &new)]), new.clone(), bad];
        let ram = Ram(Arc::new(SpinLock::new(image_with(&log))));
        Fs::open(7, alloc::boxed::Box::new(ram.clone()), false).unwrap();
        assert!(ram.0.lock()[22 * BS..23 * BS].iter().all(|&b| b == b'a'));
    }

    #[test]
    fn a_bad_journal_superblock_does_not_mount() {
        let mut img = image_with(&[]);
        img[AT * BS + jsb::MAX_LEN + 3] = 15;
        assert_eq!(open(img).err(), Some(Errno::EUCLEAN));
    }

    /// The image with an empty journal of 23 blocks in the blocks 41 to 63, and without
    /// `RECOVER`.
    fn image_with_room() -> Vec<u8> {
        let mut img = Image(image());
        let inode = img.inode(8, 0o100600, 23 * BS as u32, 1, flags::EXTENTS);
        img.extents(inode, &[(0, 23, 41)]);
        img.put32(1024 + 0xe0, 8);
        img.put32(1024 + 0x5c, layout::compat::HAS_JOURNAL);
        for b in 41..=63 {
            img.0[3 * BS + (b - 1) / 8] |= 1 << ((b - 1) % 8);
        }
        let free = layout::u32_at(&img.0, 1024 + 0xc) - 23;
        img.put32(1024 + 0xc, free);
        img.put16(2 * BS + 0xc, free as u16);
        let mut sb = header(4, 0);
        put_be32(&mut sb, jsb::BLOCK_SIZE, BS as u32);
        put_be32(&mut sb, jsb::MAX_LEN, 23);
        put_be32(&mut sb, jsb::FIRST, 1);
        put_be32(&mut sb, jsb::SEQUENCE, 9);
        put_be32(&mut sb, jsb::INCOMPAT, feature::REVOKE | feature::CSUM_V3);
        sb[jsb::UUID..jsb::UUID + 16].copy_from_slice(&UUID);
        seal(&mut sb, jsb::CHECKSUM, !0);
        img.0[41 * BS..42 * BS].copy_from_slice(&sb);
        img.0
    }

    #[test]
    fn the_journal_brings_back_the_changes_after_a_crash() {
        let clean = image_with_room();
        let ram = Ram(Arc::new(SpinLock::new(clean.clone())));
        let fs = Fs::open(7, alloc::boxed::Box::new(ram.clone()), false).unwrap();
        let root = fs.root().unwrap();
        root.create(b"dir", FileType::Directory, 0o755, 0).unwrap();
        root.symlink(b"ln", b"hello").unwrap();
        root.sync().unwrap();
        let live = ram.0.lock().clone();
        assert_ne!(layout::u32_at(&live, 1024 + 0x60) & layout::incompat::RECOVER, 0);
        let free = ram.free();

        // The crash comes before the blocks go to their places: only the journal is on the
        // disk. The two changes fit in the log, so no checkpoint wrote them before.
        let mut crash = clean;
        crash[41 * BS..].copy_from_slice(&live[41 * BS..]);
        let incompat = layout::u32_at(&crash, 1024 + 0x60) | layout::incompat::RECOVER;
        crash[1024 + 0x60..1024 + 0x64].copy_from_slice(&incompat.to_le_bytes());
        let crashed = Ram(Arc::new(SpinLock::new(crash)));
        let back = Fs::open(7, alloc::boxed::Box::new(crashed.clone()), true).unwrap();
        let names: Vec<Vec<u8>> =
            names(&*back.root().unwrap()).into_iter().map(|(n, _)| n).collect();
        assert!(names.contains(&b"dir".to_vec()) && names.contains(&b"ln".to_vec()));
        assert_eq!(crashed.free(), free);
        let disk = crashed.0.lock();
        // The superblock differs only in `RECOVER`, and the test reads its free counts.
        let diff: Vec<usize> = (2 * BS..41 * BS).filter(|&i| disk[i] != live[i]).collect();
        assert!(diff.is_empty(), "{diff:?}");
        drop(disk);
        drop((root, fs));
    }

    #[test]
    fn a_shutdown_stops_the_changes() {
        use rk_vfs::inode::shutdown::{LOGFLUSH, NOLOGFLUSH};
        let ram = Ram(Arc::new(SpinLock::new(image_with_room())));
        let fs = Fs::open(7, alloc::boxed::Box::new(ram.clone()), false).unwrap();
        let root = fs.root().unwrap();
        let kept = root.create(b"kept", FileType::Regular, 0o644, 0).unwrap();
        kept.write_at(0, b"data").unwrap();
        root.sync().unwrap();
        // A change of one block stays in memory until the next commit.
        kept.set_attr(&SetAttr { mode: Some(0o600), ..SetAttr::default() }).unwrap();
        assert_eq!(root.shutdown(3), Err(Errno::EINVAL));
        root.shutdown(NOLOGFLUSH).unwrap();
        root.shutdown(LOGFLUSH).unwrap();
        assert_eq!(root.create(b"new", FileType::Regular, 0o644, 0).err(), Some(Errno::EIO));
        assert_eq!(kept.read_at(0, &mut [0u8; 4]), Err(Errno::EIO));
        assert_eq!(kept.sync(), Err(Errno::EIO));
        drop((kept, root, fs));
        // The unmount leaves the journal, and the mount replays it without the lost change.
        let disk = ram.0.lock().clone();
        assert_ne!(layout::u32_at(&disk, 1024 + 0x60) & layout::incompat::RECOVER, 0);
        let fs = Fs::open(7, alloc::boxed::Box::new(ram.clone()), false).unwrap();
        let kept = fs.root().unwrap().lookup(b"kept").unwrap();
        assert_eq!(read_all(&*kept), b"data");
        assert_eq!(kept.metadata().mode & 0o777, 0o644);
    }

    #[test]
    fn a_checkpoint_empties_the_journal() {
        use rk_vfs::inode::checkpoint::{DISCARD, DRY_RUN, ZEROOUT};
        let (fs, _ram) = open_rw();
        assert_eq!(fs.root().unwrap().checkpoint(DRY_RUN), Err(Errno::ENODEV));
        let ram = Ram(Arc::new(SpinLock::new(image_with_room())));
        let fs = Fs::open(7, alloc::boxed::Box::new(ram.clone()), false).unwrap();
        let root = fs.root().unwrap();
        assert_eq!(root.checkpoint(DISCARD | ZEROOUT), Err(Errno::EINVAL));
        assert_eq!(root.checkpoint(8), Err(Errno::EINVAL));
        assert_eq!(root.checkpoint(DISCARD), Err(Errno::EOPNOTSUPP));
        root.checkpoint(DRY_RUN).unwrap();
        for i in 0..3 {
            root.create(format!("d{i}").as_bytes(), FileType::Directory, 0o755, 0).unwrap();
        }
        root.sync().unwrap();
        assert!(ram.0.lock()[42 * BS..64 * BS].iter().any(|&b| b != 0));
        root.checkpoint(ZEROOUT).unwrap();
        let disk = ram.0.lock().clone();
        assert_eq!(be32(&disk, 41 * BS + jsb::START), 0);
        assert!(disk[42 * BS..64 * BS].iter().all(|&b| b == 0));
        // The journal takes new transactions after it.
        root.create(b"after", FileType::Regular, 0o644, 0).unwrap();
        drop((root, fs));
        let fs = Fs::open(7, alloc::boxed::Box::new(ram.clone()), false).unwrap();
        assert_eq!(names(&*fs.root().unwrap()).len(), 4 + 3 + 1);
    }

    #[test]
    fn the_unmount_leaves_a_clean_journal() {
        let ram = Ram(Arc::new(SpinLock::new(image_with_room())));
        let fs = Fs::open(7, alloc::boxed::Box::new(ram.clone()), false).unwrap();
        let root = fs.root().unwrap();
        for i in 0..6 {
            root.create(format!("d{i}").as_bytes(), FileType::Directory, 0o755, 0).unwrap();
        }
        // The transaction is a quarter of the log, so it commits without a sync.
        assert_ne!(be32(&ram.0.lock(), 41 * BS + jsb::START), 0);
        drop((root, fs));
        let disk = ram.0.lock().clone();
        assert_eq!(layout::u32_at(&disk, 1024 + 0x60) & layout::incompat::RECOVER, 0);
        assert_eq!(be32(&disk, 41 * BS + jsb::START), 0);
        let fs = Fs::open(7, alloc::boxed::Box::new(ram.clone()), false).unwrap();
        assert_eq!(names(&*fs.root().unwrap()).len(), 4 + 6);
    }

    #[test]
    fn an_open_file_without_links_is_an_orphan() {
        let ram = Ram(Arc::new(SpinLock::new(image_with_room())));
        let free = ram.free();
        let fs = Fs::open(7, alloc::boxed::Box::new(ram.clone()), false).unwrap();
        let root = fs.root().unwrap();
        let file = root.create(b"tmp", FileType::Regular, 0o600, 0).unwrap();
        file.write_at(0, &vec![b't'; 2 * BS]).unwrap();
        let ino = file.metadata().ino as u32;
        root.unlink(b"tmp").unwrap();
        root.sync().unwrap();
        assert_eq!(ram.u32_at(1024 + layout::sb::LAST_ORPHAN), ino);

        // A crash now leaves the orphan, and the next mount frees it.
        let crashed = Ram(Arc::new(SpinLock::new(ram.0.lock().clone())));
        drop(Fs::open(7, alloc::boxed::Box::new(crashed.clone()), false).unwrap());
        assert_eq!(crashed.u32_at(1024 + layout::sb::LAST_ORPHAN), 0);
        assert_eq!(crashed.free(), free);

        drop(file);
        assert_eq!(fs.meta.lock().sb[layout::sb::LAST_ORPHAN], 0);
        drop((root, fs));
        assert_eq!(ram.u32_at(1024 + layout::sb::LAST_ORPHAN), 0);
        assert_eq!(ram.free(), free);
    }
}

#[test]
fn extended_attributes_stay_after_a_mount() {
    let (fs, ram) = open_rw();
    let free = ram.free();
    let root = fs.root().unwrap();
    let file = root.create(b"x", FileType::Regular, 0o644, 0).unwrap();
    file.set_xattr(b"user.small", b"1", 0).unwrap();
    file.set_xattr(b"trusted.overlay.opaque", b"y", 0).unwrap();
    file.set_xattr(b"user.empty", b"", 0).unwrap();
    // The small attributes stay in the inode, so the file has no block.
    assert_eq!(file.metadata().blocks, 0);
    assert_eq!(ram.free().0, free.0);
    assert_eq!(file.set_xattr(b"user.small", b"2", XATTR_CREATE), Err(Errno::EEXIST));
    assert_eq!(file.set_xattr(b"user.none", b"2", XATTR_REPLACE), Err(Errno::ENODATA));
    assert_eq!(file.set_xattr(b"other.a", b"2", 0), Err(Errno::EOPNOTSUPP));
    // A large value goes to a block.
    file.set_xattr(b"user.large", &[7u8; 300], 0).unwrap();
    assert_eq!(file.metadata().blocks, (BS / 512) as u64);
    assert_eq!(ram.free().0, free.0 - 1);
    drop((file, root, fs));

    let fs = Fs::open(7, alloc::boxed::Box::new(ram.clone()), false).unwrap();
    let file = fs.root().unwrap().lookup(b"x").unwrap();
    assert_eq!(file.get_xattr(b"user.small").unwrap(), b"1");
    assert_eq!(file.get_xattr(b"trusted.overlay.opaque").unwrap(), b"y");
    assert_eq!(file.get_xattr(b"user.empty").unwrap(), b"");
    assert_eq!(file.get_xattr(b"user.large").unwrap(), [7u8; 300]);
    assert_eq!(file.get_xattr(b"user.none"), Err(Errno::ENODATA));
    let mut names = file.list_xattr().unwrap();
    names.sort();
    assert_eq!(
        names,
        [&b"trusted.overlay.opaque"[..], b"user.empty", b"user.large", b"user.small"]
    );
    // The removal of the large value frees the block.
    file.remove_xattr(b"user.large").unwrap();
    assert_eq!(file.remove_xattr(b"user.large"), Err(Errno::ENODATA));
    assert_eq!(file.metadata().blocks, 0);
    assert_eq!(ram.free().0, free.0);
}

#[test]
fn unlink_frees_the_attribute_block() {
    let (fs, ram) = open_rw();
    let free = ram.free();
    let root = fs.root().unwrap();
    let file = root.create(b"x", FileType::Regular, 0o644, 0).unwrap();
    file.set_xattr(b"user.large", &[1u8; 600], 0).unwrap();
    assert_eq!(file.set_xattr(b"user.huge", &[1u8; BS], 0), Err(Errno::ENOSPC));
    assert_eq!(ram.free().0, free.0 - 1);
    root.unlink(b"x").unwrap();
    drop(file);
    assert_eq!(ram.free(), free);
}

#[test]
fn an_acl_has_the_ext4_format_on_the_disk() {
    use rk_vfs::acl::{ACCESS, Acl, Entry, UNDEFINED_ID, tag};
    let (fs, ram) = open_rw();
    let file = fs.root().unwrap().create(b"acl", FileType::Regular, 0o640, 0).unwrap();
    let e = |tag, perm, id| Entry { tag, perm, id };
    let acl = Acl(alloc::vec![
        e(tag::USER_OBJ, 6, UNDEFINED_ID),
        e(tag::USER, 4, 1000),
        e(tag::GROUP_OBJ, 4, UNDEFINED_ID),
        e(tag::MASK, 4, UNDEFINED_ID),
        e(tag::OTHER, 0, UNDEFINED_ID),
    ]);
    file.set_xattr(ACCESS, &acl.to_xattr(), 0).unwrap();
    assert_eq!(file.set_xattr(ACCESS, b"bad", 0), Err(Errno::EINVAL));
    // The disk has the version 1, one entry of 8 bytes and four entries of 4 bytes.
    let raw = fs.xattrs(&fs.inode(file.metadata().ino as u32).unwrap().raw()).unwrap();
    let disk = &raw[&(2, Vec::new())];
    assert_eq!(disk.len(), 4 + 8 + 4 * 4);
    assert_eq!(&disk[..4], &1u32.to_le_bytes());
    drop(file);
    let file = again(&ram).root().unwrap().lookup(b"acl").unwrap();
    assert_eq!(file.get_xattr(ACCESS).unwrap(), acl.to_xattr());
}
