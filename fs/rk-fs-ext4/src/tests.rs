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
fn a_new_inode_gets_the_flags_of_its_directory() {
    use rk_vfs::inode::iflags::{DAX, NOATIME, SYNC};
    let extents = 0x8_0000;
    let (fs, _ram) = open_rw();
    let dir = fs.root().unwrap().create(b"d", FileType::Directory, 0o755, 0).unwrap();
    // The DIRSYNC flag goes to the new directories only, and a FIFO gets only NOATIME.
    let dirsync = 0x1_0000;
    dir.set_attr_flags(extents | DAX | SYNC | NOATIME | dirsync).unwrap();
    let file = dir.create(b"f", FileType::Regular, 0o644, 0).unwrap();
    assert_eq!(file.attr_flags(), Ok(extents | DAX | SYNC | NOATIME));
    let sub = dir.create(b"s", FileType::Directory, 0o755, 0).unwrap();
    assert_eq!(sub.attr_flags(), Ok(extents | DAX | SYNC | NOATIME | dirsync));
    let node = dir.create(b"p", FileType::Fifo, 0o644, 0).unwrap();
    assert_eq!(node.attr_flags(), Ok(NOATIME));
    // The DAX flag cannot go with the journal data flag.
    let journal_data = 0x4000;
    assert_eq!(sub.set_attr_flags(extents | DAX | journal_data), Err(Errno::EOPNOTSUPP));
    let plain = fs.root().unwrap().create(b"g", FileType::Regular, 0o644, 0).unwrap();
    plain.set_attr_flags(extents | journal_data).unwrap();
    assert_eq!(plain.set_attr_flags(extents | journal_data | DAX), Err(Errno::EOPNOTSUPP));
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
fn a_hole_at_the_start_stays_a_hole_in_the_block_map() {
    // As ext4/005, a write to the hole after `chattr -e` gets a new block, and the data of
    // the second block stays in its place.
    let (fs, ram) = open_rw();
    let free = ram.free().0;
    let file = fs.root().unwrap().create(b"f", FileType::Regular, 0o644, 0).unwrap();
    file.write_at(BS as u64, &vec![b'b'; BS]).unwrap();
    file.set_attr_flags(0).unwrap();
    let first = file.fiemap(0, u64::MAX).unwrap();
    assert_eq!((first.len(), first[0].logical), (1, BS as u64));
    file.write_at(0, &vec![b'a'; BS]).unwrap();
    assert_eq!(file.metadata().blocks, 2 * (BS as u64 / 512));
    assert_eq!(ram.free().0, free - 2);
    let back = again(&ram).root().unwrap().lookup(b"f").unwrap();
    let data = read_all(&*back);
    assert_eq!((data[0], data[BS - 1], data[BS], data[2 * BS - 1]), (b'a', b'a', b'b', b'b'));
    let map = back.fiemap(0, u64::MAX).unwrap();
    assert!(map.iter().any(|e| e.logical == BS as u64 && e.physical == first[0].physical));
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
fn a_file_handle_finds_the_inode_until_the_inode_is_removed() {
    use rk_vfs::inode::fileid;
    let (fs, ram) = open_rw();
    let root = fs.root().unwrap();
    let file = root.create(b"f", FileType::Regular, 0o644, 0).unwrap();
    let (ty, fid) = file.file_handle().unwrap();
    assert_eq!(ty, fileid::INO32_GEN);
    assert_eq!(fid[0] as u64, file.metadata().ino);
    // A new mount reads the inode from the disk.
    root.sync().unwrap();
    let found = again(&ram).root().unwrap().inode_by_handle(ty, &fid).unwrap();
    assert_eq!(found.metadata().ino, file.metadata().ino);
    // Another generation, a reserved inode and a short handle are stale.
    let other = [fid[0], fid[1].wrapping_add(1)];
    assert_eq!(root.inode_by_handle(ty, &other).err(), Some(Errno::ESTALE));
    assert_eq!(root.inode_by_handle(ty, &[1, 0]).err(), Some(Errno::ESTALE));
    assert_eq!(root.inode_by_handle(ty, &fid[..1]).err(), Some(Errno::ESTALE));
    // An open file without a link stays, and a removed inode is stale.
    root.unlink(b"f").unwrap();
    assert!(root.inode_by_handle(ty, &fid).is_ok());
    drop(file);
    assert_eq!(root.inode_by_handle(ty, &fid).err(), Some(Errno::ESTALE));
}

#[test]
fn a_removed_entry_leaves_no_name_on_the_disk() {
    let (fs, ram) = open_rw();
    let root = fs.root().unwrap();
    let dir = root.create(b"d", FileType::Directory, 0o755, 0).unwrap();
    // Links with records of 72 bytes fill the first block, so the second block starts with an
    // entry.
    let keep = dir.create(b"keep", FileType::Regular, 0o644, 0).unwrap();
    let name = |i: usize| format!("wipe-{i:0>58}").into_bytes();
    for i in 0..20 {
        dir.link(&name(i), &keep).unwrap();
    }
    for i in 0..20 {
        dir.unlink(&name(i)).unwrap();
    }
    let disk = ram.0.lock().clone();
    assert!(!disk.windows(5).any(|w| w == b"wipe-"));
    assert!(disk.windows(4).any(|w| w == b"keep"));
    drop(disk);
    let back = again(&ram).root().unwrap().lookup(b"d").unwrap();
    assert_eq!(names(&*back).len(), 3);
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
fn exchange_swaps_a_file_and_a_directory() {
    let (fs, ram) = open_rw();
    let root = fs.root().unwrap();
    let sub = root.lookup(b"sub").unwrap();
    let dir = root.create(b"d", FileType::Directory, 0o755, 0).unwrap();
    assert_eq!((root.metadata().nlink, sub.metadata().nlink), (5, 2));
    root.exchange(b"d", &sub, b"old").unwrap();
    assert_eq!((root.metadata().nlink, sub.metadata().nlink), (4, 3));
    assert_eq!(root.exchange(b"d", &sub, b"none"), Err(Errno::ENOENT));
    drop((dir, sub, root, fs));

    let fs = again(&ram);
    let root = fs.root().unwrap();
    let sub = root.lookup(b"sub").unwrap();
    assert_eq!(root.lookup(b"d").unwrap().metadata().size, 13 * BS as u64);
    let d = sub.lookup(b"old").unwrap();
    assert!(Arc::ptr_eq(&d.lookup(b"..").unwrap(), &sub));
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
fn a_full_disk_gives_back_the_blocks_of_a_tree_that_does_not_fit() {
    let (fs, ram) = open_rw();
    let root = fs.root().unwrap();
    // Four extents fill the root of the tree.
    let sparse = root.create(b"sparse", FileType::Regular, 0o644, 0).unwrap();
    for i in 0..4u64 {
        sparse.write_at(i * 2 * BS as u64, &[1]).unwrap();
    }
    let fill = root.create(b"fill", FileType::Regular, 0o644, 0).unwrap();
    let mut size = 0;
    while fill.write_at(size, &[2u8; BS]) == Ok(BS) {
        size += BS as u64;
    }
    // One free block is for the data, and the tree needs one more block for the fifth extent.
    fill.set_attr(&SetAttr { size: Some(size - BS as u64), ..SetAttr::default() }).unwrap();
    assert_eq!(sparse.write_at(8 * BS as u64, &[1]), Err(Errno::ENOSPC));
    assert_eq!(sparse.metadata().blocks, 4 * (BS as u64 / 512));
    let free = ram.free();
    drop((sparse, fill, root, fs));

    let fs = Fs::open(7, alloc::boxed::Box::new(ram.clone()), false).unwrap();
    assert_eq!(ram.free(), free);
    let root = fs.root().unwrap();
    let fill = root.lookup(b"fill").unwrap();
    assert_eq!(fill.write_at(size - BS as u64, &[3u8; BS]), Ok(BS));
}

#[test]
fn a_full_disk_gives_back_the_blocks_of_fallocate_when_the_tree_does_not_fit() {
    use rk_vfs::inode::falloc::KEEP_SIZE;
    let (fs, ram) = open_rw();
    let root = fs.root().unwrap();
    let sparse = root.create(b"sparse", FileType::Regular, 0o644, 0).unwrap();
    for i in 0..4u64 {
        sparse.write_at(i * 2 * BS as u64, &[1]).unwrap();
    }
    let fill = root.create(b"fill", FileType::Regular, 0o644, 0).unwrap();
    let mut size = 0;
    while fill.write_at(size, &[2u8; BS]) == Ok(BS) {
        size += BS as u64;
    }
    fill.set_attr(&SetAttr { size: Some(size - BS as u64), ..SetAttr::default() }).unwrap();
    assert_eq!(sparse.fallocate(KEEP_SIZE, 8 * BS as u64, BS as u64), Err(Errno::ENOSPC));
    assert_eq!(sparse.metadata().blocks, 4 * (BS as u64 / 512));
    let free = ram.free();
    drop((sparse, fill, root, fs));

    let fs = Fs::open(7, alloc::boxed::Box::new(ram.clone()), false).unwrap();
    assert_eq!(ram.free(), free);
    let fill = fs.root().unwrap().lookup(b"fill").unwrap();
    assert_eq!(fill.write_at(size - BS as u64, &[3u8; BS]), Ok(BS));
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
    fn a_new_inode_has_a_creation_time() {
        let (fs, ram) = open_rw();
        let root = fs.root().unwrap();
        let file = root.create(b"born", FileType::Regular, 0o644, 0).unwrap();
        let meta = file.metadata();
        assert_eq!(meta.btime, Some(meta.ctime));
        drop((file, root, fs));
        let fs = again(&ram);
        let meta = fs.root().unwrap().lookup(b"born").unwrap().metadata();
        assert_eq!(meta.btime, Some(meta.ctime));
    }

    #[test]
    fn the_label_changes_on_the_disk_at_once() {
        let ram = Ram(Arc::new(SpinLock::new(image_with_room())));
        let fs = Fs::open(7, alloc::boxed::Box::new(ram.clone()), false).unwrap();
        let root = fs.root().unwrap();
        root.set_label(b"label.492").unwrap();
        assert_eq!(root.label().unwrap(), b"label.492");
        assert_eq!(&ram.0.lock()[1024 + 0x78..1024 + 0x82], b"label.492\0");
        root.set_label(&[b'o'; 16]).unwrap();
        assert_eq!(root.label().unwrap(), [b'o'; 16]);
        assert_eq!(root.set_label(&[b'o'; 17]), Err(Errno::EINVAL));
        root.set_label(b"").unwrap();
        assert_eq!(root.label().unwrap(), b"");
        root.set_label(b"kept").unwrap();
        drop((root, fs));
        let fs = Fs::open(7, alloc::boxed::Box::new(ram.clone()), true).unwrap();
        assert_eq!(fs.root().unwrap().label().unwrap(), b"kept");
        assert_eq!(fs.root().unwrap().set_label(b"x"), Err(Errno::EROFS));
    }

    #[test]
    fn a_freeze_leaves_a_clean_disk_until_the_thaw() {
        let ram = Ram(Arc::new(SpinLock::new(image_with_room())));
        let fs = Fs::open(7, alloc::boxed::Box::new(ram.clone()), false).unwrap();
        let root = fs.root().unwrap();
        let file = root.create(b"file", FileType::Regular, 0o644, 0).unwrap();
        file.write_at(0, b"data").unwrap();
        assert_eq!(root.freeze(false), Err(Errno::EINVAL));
        root.freeze(true).unwrap();
        assert_eq!(root.freeze(true), Err(Errno::EBUSY));
        // The disk is clean: the journal is empty and a mount needs no replay.
        let disk = ram.0.lock().clone();
        assert_eq!(layout::u32_at(&disk, 1024 + 0x60) & layout::incompat::RECOVER, 0);
        assert_eq!(be32(&disk, 41 * BS + jsb::START), 0);
        // A read does not wait, and the access time stays.
        let atime = file.metadata().atime;
        assert_eq!(read_all(&*file), b"data");
        file.set_atime(rk_vfs::inode::Timespec { sec: 1, nsec: 0 }).unwrap();
        assert_eq!(file.metadata().atime, atime);
        root.freeze(false).unwrap();
        assert_eq!(root.freeze(false), Err(Errno::EINVAL));
        assert_ne!(layout::u32_at(&ram.0.lock(), 1024 + 0x60) & layout::incompat::RECOVER, 0);
        root.create(b"after", FileType::Regular, 0o644, 0).unwrap();
        drop((file, root, fs));
        let fs = Fs::open(7, alloc::boxed::Box::new(ram.clone()), false).unwrap();
        assert!(fs.root().unwrap().lookup(b"after").is_ok());
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
    fn a_full_disk_commits_to_use_the_blocks_that_a_change_freed() {
        let ram = Ram(Arc::new(SpinLock::new(image_with_room())));
        let fs = Fs::open(7, alloc::boxed::Box::new(ram.clone()), false).unwrap();
        let file = fs.root().unwrap().create(b"f", FileType::Regular, 0o644, 0).unwrap();
        let mut size = 0;
        while file.write_at(size, &[1u8; BS]) == Ok(BS) {
            size += BS as u64;
        }
        assert!(size > 0);
        // The freed blocks wait for the next commit, and the write after the truncate needs them.
        // This small log commits each change at once, so the test keeps the blocks busy as a
        // large log does.
        file.set_attr(&SetAttr { size: Some(0), ..SetAttr::default() }).unwrap();
        fs.busy.lock().extend(0..64);
        let mut again = 0;
        while again < size && file.write_at(again, &[2u8; BS]) == Ok(BS) {
            again += BS as u64;
        }
        assert_eq!(again, size);
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

    #[test]
    fn orphans_leave_the_list_in_any_order() {
        let ram = Ram(Arc::new(SpinLock::new(image_with_room())));
        let free = ram.free();
        let fs = Fs::open(7, alloc::boxed::Box::new(ram.clone()), false).unwrap();
        let root = fs.root().unwrap();
        let mut files: Vec<_> = (0..4u8)
            .map(|i| {
                let name = [b'o', b'0' + i];
                let file = root.create(&name, FileType::Regular, 0o600, 0).unwrap();
                root.unlink(&name).unwrap();
                Some(file)
            })
            .collect();
        let head = files[3].as_ref().unwrap().metadata().ino as u32;
        assert_eq!(fs.meta.lock().orphan_prev.len(), 4);
        // The middle, then the tail, then the head, then the last.
        for i in [1, 0, 3, 2] {
            drop(files[i].take());
            if i == 1 {
                assert_eq!(u32_at(&fs.meta.lock().sb, layout::sb::LAST_ORPHAN), head);
            }
        }
        assert_eq!(u32_at(&fs.meta.lock().sb, layout::sb::LAST_ORPHAN), 0);
        assert!(fs.meta.lock().orphan_prev.is_empty());
        drop((root, fs));
        let fs = Fs::open(7, alloc::boxed::Box::new(ram.clone()), false).unwrap();
        drop(fs);
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
fn fiemap_gives_the_extent_of_the_attributes() {
    let (fs, _ram) = open_rw();
    let file = fs.root().unwrap().create(b"x", FileType::Regular, 0o644, 0).unwrap();
    let ino = file.metadata().ino as u32;
    assert_eq!(file.fiemap_xattr(), Ok(None));
    // Attributes in the inode give the area after the extra fields.
    file.set_xattr(b"user.small", b"1", 0).unwrap();
    let raw = fs.inode(ino).unwrap().raw();
    let start = 128 + raw.extra_size() as u64;
    let block = fs.inode_at(ino).unwrap() / BS as u64;
    let e = file.fiemap_xattr().unwrap().unwrap();
    assert_eq!((e.logical, e.physical), (0, block * BS as u64 + start));
    assert_eq!((e.length, e.inline), (raw.0.len() as u64 - start, true));
    // Attributes in a block only give that block.
    file.remove_xattr(b"user.small").unwrap();
    file.set_xattr(b"user.large", &[7u8; 600], 0).unwrap();
    let acl = fs.inode(ino).unwrap().raw().file_acl();
    assert_ne!(acl, 0);
    let e = file.fiemap_xattr().unwrap().unwrap();
    assert_eq!((e.logical, e.physical, e.length, e.inline), (0, acl * BS as u64, BS as u64, false));
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

/// Mounts the image with the `ea_inode` feature for a change.
fn open_ea_inode() -> (Arc<Fs>, Ram) {
    let mut img = image();
    let incompat = layout::u32_at(&img, 1024 + 0x60) | layout::incompat::EA_INODE;
    img[1024 + 0x60..1024 + 0x64].copy_from_slice(&incompat.to_le_bytes());
    let ram = Ram(Arc::new(SpinLock::new(img)));
    (Fs::open(7, alloc::boxed::Box::new(ram.clone()), false).unwrap(), ram)
}

/// The value inode of the first entry in the inode `ino`, or in its block if `block` is true.
fn value_inode(fs: &Fs, ino: u32, block: bool) -> u32 {
    let raw = fs.inode(ino).unwrap().raw();
    if block {
        u32_at(&fs.read_block(raw.file_acl()).unwrap(), 32 + 4)
    } else {
        u32_at(&raw.0, 128 + raw.extra_size() + 4 + 4)
    }
}

#[test]
fn a_large_value_goes_to_an_inode_of_its_own() {
    let (fs, ram) = open_ea_inode();
    let free = ram.free();
    let root = fs.root().unwrap();
    let file = root.create(b"x", FileType::Regular, 0o644, 0).unwrap();
    let ino = file.metadata().ino as u32;
    let value: Vec<u8> = (0..3000u32).map(|i| i as u8).collect();
    file.set_xattr(b"user.v", &value, 0).unwrap();
    // The value has 3 blocks and an inode, and the file counts the blocks of the value.
    assert_eq!(ram.free(), (free.0 - 3, free.1 - 2));
    assert_eq!(file.metadata().blocks, 3 * (BS / 512) as u64);
    let ea = value_inode(&fs, ino, false);
    let raw = fs.read_inode(ea).unwrap();
    assert_eq!(raw.flags() & flags::EA_INODE, flags::EA_INODE);
    assert_eq!((raw.mode(), raw.links(), raw.size()), (0o100600, 1, 3000));
    assert_eq!(u32_at(&raw.0, 0x8), crc::crc32c(fs.csum_seed, &value));
    assert_eq!((u32_at(&raw.0, 0xc), u32_at(&raw.0, 0x24)), (0, 1));
    drop((file, root, fs));

    let fs = Fs::open(7, alloc::boxed::Box::new(ram.clone()), false).unwrap();
    let root = fs.root().unwrap();
    let file = root.lookup(b"x").unwrap();
    assert_eq!(file.get_xattr(b"user.v").unwrap(), value);
    // The same value keeps its inode, and a new value gets a new inode.
    file.set_xattr(b"user.v", &value, 0).unwrap();
    assert_eq!(value_inode(&fs, ino, false), ea);
    file.set_xattr(b"user.v", &[5u8; 2000], 0).unwrap();
    assert_eq!(file.get_xattr(b"user.v").unwrap(), [5u8; 2000]);
    assert_eq!(ram.free(), (free.0 - 2, free.1 - 2));
    assert_eq!(file.metadata().blocks, 2 * (BS / 512) as u64);
    // A small value goes back to the inode with the attribute.
    file.set_xattr(b"user.v", b"1", 0).unwrap();
    assert_eq!(ram.free(), (free.0, free.1 - 1));
    assert_eq!(file.metadata().blocks, 0);
    file.set_xattr(b"user.v", &value, 0).unwrap();
    file.remove_xattr(b"user.v").unwrap();
    assert_eq!(ram.free(), (free.0, free.1 - 1));
    file.set_xattr(b"user.v", &value, 0).unwrap();
    root.unlink(b"x").unwrap();
    drop(file);
    assert_eq!(ram.free(), free);
}

#[test]
fn a_value_that_does_not_fit_in_the_block_goes_to_an_inode() {
    let (fs, ram) = open_ea_inode();
    let free = ram.free();
    let root = fs.root().unwrap();
    let file = root.create(b"x", FileType::Regular, 0o644, 0).unwrap();
    let ino = file.metadata().ino as u32;
    file.set_xattr(b"user.a", &[1u8; 64], 0).unwrap();
    file.set_xattr(b"user.b", &[2u8; 700], 0).unwrap();
    file.set_xattr(b"user.c", &[3u8; 600], 0).unwrap();
    // `user.a` fills the inode. The values of `user.b` and `user.c` do not fit together in the
    // block, so the larger value goes to an inode, and both entries are in the block.
    let raw = fs.inode(ino).unwrap().raw();
    let block = fs.read_block(raw.file_acl()).unwrap();
    assert_eq!(&block[32 + 16..32 + 17], b"b");
    assert_ne!(u32_at(&block, 32 + 4), 0);
    assert_eq!(&block[52 + 16..52 + 17], b"c");
    assert_eq!(u32_at(&block, 52 + 4), 0);
    assert_eq!(ram.free(), (free.0 - 2, free.1 - 2));
    drop((file, root, fs));

    let fs = Fs::open(7, alloc::boxed::Box::new(ram.clone()), false).unwrap();
    let root = fs.root().unwrap();
    let file = root.lookup(b"x").unwrap();
    assert_eq!(file.get_xattr(b"user.a").unwrap(), [1u8; 64]);
    assert_eq!(file.get_xattr(b"user.b").unwrap(), [2u8; 700]);
    assert_eq!(file.get_xattr(b"user.c").unwrap(), [3u8; 600]);
    let ea = value_inode(&fs, ino, true);
    assert_eq!(fs.read_inode(ea).unwrap().flags() & flags::EA_INODE, flags::EA_INODE);
    // The release of the file frees the block and the value inode.
    root.unlink(b"x").unwrap();
    drop(file);
    assert_eq!(ram.free(), free);
}

#[test]
fn a_large_value_without_ea_inode_gives_enospc() {
    let (fs, ram) = open_rw();
    let free = ram.free();
    let file = fs.root().unwrap().create(b"x", FileType::Regular, 0o644, 0).unwrap();
    assert_eq!(file.set_xattr(b"user.v", &[1u8; 3000], 0), Err(Errno::ENOSPC));
    assert_eq!(ram.free(), (free.0, free.1 - 1));
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

#[test]
fn an_online_resize_makes_the_last_group_longer() {
    let (fs, ram) = open_rw();
    ram.0.lock().resize(200 * BS, 0);
    let (blocks, free) = (fs.stat().blocks, ram.free());
    assert_eq!(fs.resize(40), Err(Errno::EINVAL));
    assert_eq!(fs.resize(201), Err(Errno::EINVAL));
    fs.resize(200).unwrap();
    assert_eq!(fs.stat().blocks, blocks + 136);
    assert_eq!(ram.free(), (free.0 + 136, free.1));
    assert_eq!(ram.u32_at(1024 + 0x4), 200);
    // The new blocks are free, and a file can use them.
    let file = fs.root().unwrap().create(b"big", FileType::Regular, 0o644, 0).unwrap();
    file.write_at(0, &[7u8; 100 * BS]).unwrap();
    drop(file);
    let fs = again(&ram);
    assert_eq!(fs.blocks_count(), 200);
    assert_eq!(read_all(&*fs.root().unwrap().lookup(b"big").unwrap()), [7u8; 100 * BS]);
}

#[test]
fn an_online_resize_adds_a_group() {
    let (fs, ram) = open_rw();
    let count = 1 + 8192 + 100;
    ram.0.lock().resize(count * BS, 0);
    let free = ram.free();
    fs.resize(count as u64).unwrap();
    // The new group has a copy of the superblock and of the descriptors, two bitmaps and an
    // inode table of 8 blocks.
    let added = (8192 - 63) + (100 - 12);
    assert_eq!(ram.free(), (free.0 + added, free.1 + 32));
    assert_eq!(ram.u32_at(1024), 64);
    let fs = again(&ram);
    assert_eq!((fs.group_count(), fs.inodes_count()), (2, 64));
    let desc = fs.group(1).unwrap();
    assert_eq!((desc.block_bitmap, desc.inode_bitmap, desc.inode_table), (8195, 8196, 8197));
    // The copy of the superblock in the group 1 tells its group.
    assert_eq!(layout::u16_at(&ram.0.lock(), 8193 * BS + 0x5a), 1);
    drop(fs);
    // Each inode of the group 0 is in use, so a new inode is in the group 1.
    let fs = Fs::open(7, alloc::boxed::Box::new(ram.clone()), false).unwrap();
    let root = fs.root().unwrap();
    for i in 0..18 {
        root.create(format!("f{i}").as_bytes(), FileType::Regular, 0o644, 0).unwrap();
    }
    let last = root.create(b"last", FileType::Regular, 0o644, 0).unwrap();
    assert!(last.metadata().ino > 32);
}

#[test]
fn a_bad_orphan_ends_the_list_and_stays() {
    // The inode 2 is reserved, and the inode 20 is not in use.
    for ino in [2, 5, 20, 99] {
        let mut img = image();
        img[1024 + 0xe8..1024 + 0xec].copy_from_slice(&(ino as u32).to_le_bytes());
        let ram = Ram(Arc::new(SpinLock::new(img)));
        let free = ram.free();
        let fs = Fs::open(7, alloc::boxed::Box::new(ram.clone()), false).unwrap();
        drop(fs);
        assert_eq!(ram.u32_at(1024 + 0xe8), 0);
        assert_eq!(ram.free(), free);
        assert_eq!(again(&ram).root().unwrap().metadata().nlink, 4);
    }
}

#[test]
fn a_change_makes_the_extra_fields_of_an_inode_larger() {
    let mut img = image();
    img[1024 + 0x64..1024 + 0x68].copy_from_slice(&layout::ro_compat::EXTRA_ISIZE.to_le_bytes());
    img[1024 + 0x15e..1024 + 0x160].copy_from_slice(&32u16.to_le_bytes());
    let ram = Ram(Arc::new(SpinLock::new(img)));
    let fs = Fs::open(7, alloc::boxed::Box::new(ram.clone()), false).unwrap();
    let file = fs.root().unwrap().create(b"x", FileType::Regular, 0o644, 0).unwrap();
    let ino = file.metadata().ino as u32;
    for name in [&b"user.a"[..], b"user.b", b"user.c"] {
        file.set_xattr(name, b"12345678", 0).unwrap();
    }
    // The three attributes fit in the inode.
    assert_eq!(fs.inode(ino).unwrap().raw().file_acl(), 0);
    drop((file, fs));
    ram.0.lock()[1024 + 0x15e..1024 + 0x160].copy_from_slice(&64u16.to_le_bytes());
    let fs = Fs::open(7, alloc::boxed::Box::new(ram.clone()), false).unwrap();
    let file = fs.root().unwrap().lookup(b"x").unwrap();
    let free = ram.free().0;
    // A truncate saves the inode two times. The second save does not grow the fields again.
    file.set_attr(&SetAttr { size: Some(0), ..SetAttr::default() }).unwrap();
    drop((file, fs));
    // The extra fields have 64 bytes, and one attribute moved to a block.
    assert_eq!(ram.free().0, free - 1);
    let fs = again(&ram);
    let raw = fs.inode(ino).unwrap().raw();
    assert_eq!(raw.extra_size(), 64);
    assert_ne!(raw.file_acl(), 0);
    let file = fs.root().unwrap().lookup(b"x").unwrap();
    for name in [&b"user.a"[..], b"user.b", b"user.c"] {
        assert_eq!(file.get_xattr(name).unwrap(), b"12345678");
    }
}

/// A disk that keeps the discards, as bytes.
struct Discards(Ram, Arc<SpinLock<Vec<(u64, u64)>>>);

impl Disk for Discards {
    fn read(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        self.0.read(offset, buf)
    }

    fn write(&self, offset: u64, buf: &[u8]) -> Result<()> {
        self.0.write(offset, buf)
    }

    fn can_discard(&self) -> bool {
        true
    }

    fn discard(&self, offset: u64, len: u64) -> Result<()> {
        self.1.lock().push((offset, len));
        Ok(())
    }
}

#[test]
fn fitrim_discards_the_runs_of_free_blocks() {
    let (fs, ram) = open_rw();
    assert_eq!(fs.trim(0, u64::MAX, 0), Err(Errno::EOPNOTSUPP));
    drop(fs);
    let done = Arc::new(SpinLock::new(Vec::new()));
    let disk = Discards(ram.clone(), done.clone());
    let fs = Fs::open(7, alloc::boxed::Box::new(disk), false).unwrap();
    let free = ram.free();
    let bs = BS as u64;
    // The free runs of the image are 13 to 19, 23, 27 to 29, 31 to 39 and 41 to 63.
    assert_eq!(fs.trim(0, u64::MAX, 0), Ok(43 * bs));
    let runs: Vec<(u64, u64)> = done.lock().iter().map(|&(at, len)| (at / bs, len / bs)).collect();
    assert_eq!(runs, [(13, 7), (23, 1), (27, 3), (31, 9), (41, 23)]);
    assert_eq!(ram.free(), free);
    // A run that is shorter than `minlen` stays, and the range cuts the runs.
    assert_eq!(fs.trim(0, u64::MAX, 4 * bs), Ok(39 * bs));
    assert_eq!(fs.trim(14 * bs, 3 * bs, 0), Ok(3 * bs));
    assert_eq!(fs.trim(0, bs, 0), Ok(0));
    // A start past the end, a range of less than a block and a `minlen` of more than a group
    // are not valid.
    assert_eq!(fs.trim(64 * bs, bs, 0), Err(Errno::EINVAL));
    assert_eq!(fs.trim(0, bs - 1, 0), Err(Errno::EINVAL));
    assert_eq!(fs.trim(0, u64::MAX, 8193 * bs), Err(Errno::EINVAL));
}

#[test]
fn a_tmpfile_is_an_orphan_until_a_link() {
    let (fs, ram) = open_rw();
    let free = ram.free();
    let root = fs.root().unwrap();
    // A file without a link goes when no one uses it.
    let gone = root.tmpfile(0o600).unwrap();
    assert_eq!(gone.metadata().nlink, 0);
    gone.write_at(0, b"data").unwrap();
    assert_eq!(ram.u32_at(1024 + layout::sb::LAST_ORPHAN), gone.metadata().ino as u32);
    drop(gone);
    assert_eq!(ram.free(), free);
    assert_eq!(ram.u32_at(1024 + layout::sb::LAST_ORPHAN), 0);
    // A link gives the file a name, and the file leaves the list of orphans.
    let kept = root.tmpfile(0o600).unwrap();
    kept.write_at(0, b"kept").unwrap();
    root.link(b"kept", &kept).unwrap();
    assert_eq!(kept.metadata().nlink, 1);
    assert_eq!(ram.u32_at(1024 + layout::sb::LAST_ORPHAN), 0);
    drop((kept, root, fs));

    let fs = again(&ram);
    assert_eq!(read_all(&*fs.root().unwrap().lookup(b"kept").unwrap()), b"kept");
}

mod htree {
    use super::*;
    use crate::htree::dirhash;

    /// The seed 01234567-89ab-cdef-0011-223344556677 of `dx_hash -s` of debugfs.
    const SEED: [u32; 4] = [0x6745_2301, 0xefcd_ab89, 0x3322_1100, 0x7766_5544];

    #[test]
    fn the_hash_of_a_name_is_the_hash_of_linux() {
        // The values are from `debugfs -R "dx_hash -h VERSION -s SEED NAME"` of e2fsprogs 1.47.
        let long = "café-a-long-name-of-more-than-thirty-two-bytes".as_bytes();
        let cases: [(u8, &[u8], u32, u32); 9] = [
            (0, b"hello", 0x3225_2546, 0),
            (1, b"hello", 0x87d8_61fe, 0x9b29_5f1b),
            (2, b"hello", 0x6f5b_b1a8, 0x2319_17c2),
            (0, long, 0x883d_51fe, 0),
            (1, long, 0x3d36_8cf8, 0x9f76_21ea),
            (2, long, 0x12c7_0d6e, 0xaf46_33eb),
            (3, long, 0x7f01_bf16, 0),
            (4, long, 0x8724_9ad0, 0x312a_db8f),
            (5, long, 0x908e_49de, 0x0a34_3037),
        ];
        for (version, name, hash, minor) in cases {
            assert_eq!(dirhash(version, &SEED, name), Some((hash, minor)), "version {version}");
        }
        // A seed of zeros gives the default seed.
        assert_eq!(dirhash(1, &[0; 4], b"hello"), Some((0x1746_da32, 0x4200_13b5)));
        assert_eq!(dirhash(6, &SEED, b"hello"), None);
    }

    /// The test image with `blocks` blocks, `dir_index`, the seed [`SEED`] and the half MD4
    /// hash. With `csum`, the image also has `metadata_csum`, and the block of the root ends with
    /// a checksum record.
    fn htree_image(blocks: usize, csum: bool) -> Vec<u8> {
        let mut img = Image(image());
        img.0.resize(blocks * BS, 0);
        let sb = 1024;
        let more = (blocks - 64) as u32;
        img.put32(sb + 0x4, blocks as u32);
        img.put32(sb + 0xc, layout::u32_at(&img.0, sb + 0xc) + more);
        img.put16(2 * BS + 0xc, layout::u16_at(&img.0, 2 * BS + 0xc) + more as u16);
        for b in 64..blocks {
            img.0[3 * BS + (b - 1) / 8] &= !(1 << ((b - 1) % 8));
        }
        img.put32(sb + 0x5c, layout::compat::DIR_INDEX);
        for (i, &word) in SEED.iter().enumerate() {
            img.put32(sb + 0xec + 4 * i, word);
        }
        img.0[sb + 0xfc] = 1;
        if csum {
            img.put32(sb + 0x64, layout::ro_compat::METADATA_CSUM);
            let mut at = 20 * BS;
            loop {
                let rec = usize::from(layout::u16_at(&img.0, at + 4));
                if at + rec == 21 * BS {
                    img.put16(at + 4, (rec - 12) as u16);
                    break;
                }
                at += rec;
            }
            img.put16(21 * BS - 12 + 4, 12);
            img.0[21 * BS - 12 + 7] = 0xde;
        }
        img.0
    }

    /// Checks the index of the directory `ino` as fsck does: the limits, the order of the
    /// hashes, the hash of each name in its leaf, one use of each block, and the checksums with
    /// `metadata_csum`. Gives the number of index levels and the names in the leaves.
    fn check_index(fs: &Fs, ino: u32) -> (u8, Vec<Vec<u8>>) {
        let raw = fs.read_inode(ino).unwrap();
        assert_ne!(raw.flags() & flags::INDEX, 0);
        let csum = fs.metadata_csum();
        let tail = if csum { 8 } else { 0 };
        let block = |lblock: u64| fs.read_block(fs.map(&raw, lblock).unwrap().unwrap().0).unwrap();
        let root = block(0);
        assert_eq!(layout::u16_at(&root, 16), BS as u16 - 12);
        assert_eq!((root[28], root[29], root[31]), (1, 8, 0));
        let levels = root[30];
        let mut names = Vec::new();
        let mut used = vec![0];
        let mut todo = vec![(root, 32, 0, u32::MAX, 0)];
        while let Some((data, base, lo, hi, depth)) = todo.pop() {
            let limit = usize::from(layout::u16_at(&data, base));
            let count = usize::from(layout::u16_at(&data, base + 2));
            assert_eq!(limit, (BS - base - tail) / 8);
            assert!(count >= 1 && count <= limit);
            if csum {
                let t = base + 8 * limit;
                let c = crc::crc32c(fs.inode_seed(ino, &raw), &data[..base + 8 * count]);
                let c = crc::crc32c(crc::crc32c(c, &data[t..t + 4]), &[0; 4]);
                assert_eq!(layout::u32_at(&data, t + 4), c);
            }
            for i in 0..count {
                let start = if i == 0 { lo } else { layout::u32_at(&data, base + 8 * i) };
                let end = if i + 1 < count { layout::u32_at(&data, base + 8 * i + 8) } else { hi };
                assert!(lo <= start && start <= end && end <= hi);
                let child = u64::from(layout::u32_at(&data, base + 8 * i + 4));
                assert!(!used.contains(&child));
                used.push(child);
                let leaf = block(child);
                if depth < levels {
                    assert_eq!(usize::from(layout::u16_at(&leaf, 4)), BS);
                    todo.push((leaf, 8, start, end, depth + 1));
                    continue;
                }
                if csum {
                    let c = crc::crc32c(fs.inode_seed(ino, &raw), &leaf[..BS - 12]);
                    assert_eq!(layout::u32_at(&leaf, BS - 4), c);
                }
                let mut at = 0;
                while at < if csum { BS - 12 } else { BS } {
                    let rec = usize::from(layout::u16_at(&leaf, at + 4));
                    let len = usize::from(leaf[at + 6]);
                    if layout::u32_at(&leaf, at) != 0 {
                        let name = &leaf[at + 8..at + 8 + len];
                        let hash = dirhash(1, &SEED, name).unwrap().0;
                        assert!(start & !1 <= hash && hash <= end & !1);
                        names.push(name.to_vec());
                    }
                    at += rec;
                }
            }
        }
        assert_eq!(used.len() as u64, raw.size() / BS as u64);
        (levels, names)
    }

    fn mount(ram: &Ram) -> Arc<Fs> {
        Fs::open(7, alloc::boxed::Box::new(ram.clone()), false).unwrap()
    }

    fn short(i: usize) -> Vec<u8> {
        format!("name-{i:0>40}").into_bytes()
    }

    #[test]
    fn a_full_directory_gets_an_index_that_finds_each_name() {
        let ram = Ram(Arc::new(SpinLock::new(htree_image(1024, false))));
        let fs = mount(&ram);
        let big = fs.root().unwrap().create(b"big", FileType::Directory, 0o755, 0).unwrap();
        let ino = big.metadata().ino as u32;
        let file = big.create(b"file", FileType::Regular, 0o644, 0).unwrap();
        for i in 0..300 {
            big.link(&short(i), &file).unwrap();
        }
        assert_eq!(big.link(&short(7), &file), Err(Errno::EEXIST));
        drop((file, big, fs));

        let fs = again(&ram);
        let (levels, mut names) = check_index(&fs, ino);
        assert_eq!(levels, 0);
        names.sort();
        let mut want: Vec<Vec<u8>> = (0..300).map(short).collect();
        want.push(b"file".to_vec());
        want.sort();
        assert_eq!(names, want);
        let big = fs.root().unwrap().lookup(b"big").unwrap();
        assert_eq!(super::names(&*big).len(), 2 + 301);
        for i in 0..300 {
            assert!(big.lookup(&short(i)).is_ok());
        }
        assert_eq!(big.lookup(b"name-none").err(), Some(Errno::ENOENT));
        drop((big, fs));

        // Remove some names, and rename others in the directory and to `sub`.
        let fs = mount(&ram);
        let root = fs.root().unwrap();
        let big = root.lookup(b"big").unwrap();
        for i in (0..300).step_by(3) {
            big.unlink(&short(i)).unwrap();
        }
        for i in (1..300).step_by(3) {
            big.rename(&short(i), &big, format!("renamed-{i}").as_bytes()).unwrap();
        }
        big.rename(&short(2), &root.lookup(b"sub").unwrap(), b"moved").unwrap();
        drop((big, root, fs));

        let fs = again(&ram);
        let (_, names) = check_index(&fs, ino);
        assert_eq!(names.len(), 1 + 100 + 99);
        let big = fs.root().unwrap().lookup(b"big").unwrap();
        for i in 0..300 {
            let found = big.lookup(&short(i)).is_ok();
            assert_eq!(found, i % 3 == 2 && i != 2);
            if i % 3 == 1 {
                assert!(big.lookup(format!("renamed-{i}").as_bytes()).is_ok());
            }
        }
        assert!(fs.root().unwrap().lookup(b"sub").unwrap().lookup(b"moved").is_ok());
    }

    #[test]
    fn the_moved_entries_leave_no_old_names() {
        // As ext4/048, the change to an index and each split of a leaf leave zeros where the
        // moved entries were, so each name is on the disk only once.
        let ram = Ram(Arc::new(SpinLock::new(htree_image(1024, false))));
        let fs = mount(&ram);
        let big = fs.root().unwrap().create(b"big", FileType::Directory, 0o755, 0).unwrap();
        let ino = big.metadata().ino as u32;
        let file = big.create(b"file", FileType::Regular, 0o644, 0).unwrap();
        for i in 0..300 {
            big.link(&short(i), &file).unwrap();
        }
        drop((file, big, fs));
        let fs = again(&ram);
        assert_eq!(check_index(&fs, ino).1.len(), 301);
        let disk = ram.0.lock().clone();
        let mut found: Vec<&[u8]> = disk
            .windows(5)
            .enumerate()
            .filter(|(_, w)| *w == b"name-")
            .map(|(at, _)| &disk[at..at + 45])
            .collect();
        found.sort_unstable();
        let want: Vec<Vec<u8>> = (0..300).map(short).collect();
        assert_eq!(found, want.iter().map(Vec::as_slice).collect::<Vec<_>>());
    }

    #[test]
    fn the_index_gets_a_second_level_with_checksums() {
        let ram = Ram(Arc::new(SpinLock::new(htree_image(2048, true))));
        let fs = mount(&ram);
        let root = fs.root().unwrap();
        let big = root.create(b"big", FileType::Directory, 0o755, 0).unwrap();
        let ino = big.metadata().ino as u32;
        let file = big.create(b"file", FileType::Regular, 0o644, 0).unwrap();
        let long = |i: usize| format!("{i:0>250}").into_bytes();
        for i in 0..450 {
            big.link(&long(i), &file).unwrap();
        }
        drop((file, big, root, fs));

        let fs = again(&ram);
        let (levels, names) = check_index(&fs, ino);
        assert_eq!((levels, names.len()), (1, 451));
        let big = fs.root().unwrap().lookup(b"big").unwrap();
        for i in 0..450 {
            assert!(big.lookup(&long(i)).is_ok());
        }
        drop((big, fs));

        // An empty indexed directory can be removed.
        let fs = mount(&ram);
        let root = fs.root().unwrap();
        let big = root.lookup(b"big").unwrap();
        for i in 0..450 {
            big.unlink(&long(i)).unwrap();
        }
        big.unlink(b"file").unwrap();
        drop(big);
        root.rmdir(b"big").unwrap();
    }

    #[test]
    fn without_dir_index_an_indexed_directory_becomes_a_list() {
        let ram = Ram(Arc::new(SpinLock::new(htree_image(1024, false))));
        let fs = mount(&ram);
        let big = fs.root().unwrap().create(b"big", FileType::Directory, 0o755, 0).unwrap();
        let ino = big.metadata().ino as u32;
        let file = big.create(b"file", FileType::Regular, 0o644, 0).unwrap();
        for i in 0..100 {
            big.link(&short(i), &file).unwrap();
        }
        drop((file, big, fs));
        check_index(&again(&ram), ino);
        ram.0.lock()[1024 + 0x5c] = 0;
        let fs = mount(&ram);
        let big = fs.root().unwrap().lookup(b"big").unwrap();
        big.link(b"new", &big.lookup(b"file").unwrap()).unwrap();
        drop(big);
        assert_eq!(fs.read_inode(ino).unwrap().flags() & flags::INDEX, 0);
        let big = fs.root().unwrap().lookup(b"big").unwrap();
        for i in 0..100 {
            assert!(big.lookup(&short(i)).is_ok());
        }
        assert!(big.lookup(b"new").is_ok());
    }

    /// Makes the directory `big` with an index, and sets its link count to `links` on the
    /// disk. With `dir_nlink`, the image has the feature. Gives the inode of `big`.
    fn many_links(ram: &Ram, links: u16, dir_nlink: bool) -> u32 {
        let fs = mount(ram);
        let big = fs.root().unwrap().create(b"big", FileType::Directory, 0o755, 0).unwrap();
        let ino = big.metadata().ino as u32;
        let file = big.create(b"file", FileType::Regular, 0o644, 0).unwrap();
        for i in 0..100 {
            big.link(&short(i), &file).unwrap();
        }
        drop((file, big, fs));
        let mut img = ram.0.lock();
        let at = INODE_TABLE * BS + (ino as usize - 1) * 256 + 0x1a;
        img[at..at + 2].copy_from_slice(&links.to_le_bytes());
        if dir_nlink {
            img[1024 + 0x64] |= layout::ro_compat::DIR_NLINK as u8;
        }
        ino
    }

    #[test]
    fn with_dir_nlink_a_directory_with_too_many_links_has_one() {
        let ram = Ram(Arc::new(SpinLock::new(htree_image(1024, false))));
        let ino = many_links(&ram, 64998, true);
        let fs = mount(&ram);
        let root: InodeRef = fs.root().unwrap();
        let big = root.lookup(b"big").unwrap();
        big.create(b"d0", FileType::Directory, 0o755, 0).unwrap();
        big.create(b"d1", FileType::Directory, 0o755, 0).unwrap();
        assert_eq!(big.metadata().nlink, 65000);
        big.create(b"d2", FileType::Directory, 0o755, 0).unwrap();
        assert_eq!(big.metadata().nlink, 1);
        big.create(b"d3", FileType::Directory, 0o755, 0).unwrap();
        assert_eq!(big.metadata().nlink, 1);
        // The count stays 1 after a removal and after renames out of and into the directory.
        big.rmdir(b"d3").unwrap();
        assert_eq!(big.metadata().nlink, 1);
        big.rename(b"d2", &root, b"out").unwrap();
        assert_eq!((big.metadata().nlink, root.metadata().nlink), (1, 6));
        root.rename(b"out", &big, b"d2").unwrap();
        big.rename(b"d1", &big, b"d0").unwrap();
        assert_eq!((big.metadata().nlink, root.metadata().nlink), (1, 5));
        drop((big, root, fs));
        assert_eq!(again(&ram).read_inode(ino).unwrap().links(), 1);
    }

    #[test]
    fn without_dir_nlink_a_directory_stops_at_the_link_limit() {
        let ram = Ram(Arc::new(SpinLock::new(htree_image(1024, false))));
        many_links(&ram, 64999, false);
        let fs = mount(&ram);
        let root: InodeRef = fs.root().unwrap();
        let big = root.lookup(b"big").unwrap();
        big.create(b"d0", FileType::Directory, 0o755, 0).unwrap();
        assert_eq!(big.metadata().nlink, 65000);
        assert_eq!(big.create(b"d1", FileType::Directory, 0o755, 0).err(), Some(Errno::EMLINK));
        root.create(b"d1", FileType::Directory, 0o755, 0).unwrap();
        assert_eq!(root.rename(b"d1", &big, b"d1"), Err(Errno::EMLINK));
        big.create(b"f", FileType::Regular, 0o644, 0).unwrap();
        big.rmdir(b"d0").unwrap();
        assert_eq!(big.metadata().nlink, 64999);
        root.rename(b"d1", &big, b"d1").unwrap();
        assert_eq!(big.metadata().nlink, 65000);
    }
}

#[test]
fn move_extents_swaps_the_blocks_and_keeps_the_data() {
    use rk_vfs::inode::falloc::KEEP_SIZE;
    // The block of the disk of each block of the file, and if it has data.
    let blocks = |inode: &InodeRef| -> Vec<(u64, bool)> {
        let mut out = Vec::new();
        for e in inode.fiemap(0, u64::MAX).unwrap() {
            for i in 0..e.length / BS as u64 {
                out.push((e.physical / BS as u64 + i, !e.unwritten));
            }
        }
        out
    };
    let (fs, ram) = open_rw();
    let root = fs.root().unwrap();
    let orig = root.create(b"f", FileType::Regular, 0o644, 0).unwrap();
    // Writes from the end make more than one extent.
    for (i, c) in b"abcd".iter().enumerate().rev() {
        orig.write_at((i * BS) as u64, &vec![*c; BS]).unwrap();
    }
    orig.fallocate(KEEP_SIZE, 4 * BS as u64, 4 * BS as u64).unwrap();
    let donor = root.create(b"d", FileType::Regular, 0o600, 0).unwrap();
    donor.fallocate(0, 0, 8 * BS as u64).unwrap();
    let (orig_before, donor_before) = (blocks(&orig), blocks(&donor));
    let first = orig.fiemap(0, u64::MAX).unwrap();
    let free = ram.free().0;
    // The blocks past the end of the original file do not move.
    assert_eq!(orig.move_extents(&donor, 0, 0, 8), Ok(4));
    assert_eq!(ram.free().0, free);
    assert_eq!(&read_all(&*orig).chunks(BS).map(|c| c[0]).collect::<Vec<_>>(), b"abcd");
    let (orig_after, donor_after) = (blocks(&orig), blocks(&donor));
    // The original file has the blocks of the donor, with data, and the donor has the old
    // blocks of the original file, with their data.
    let with_data: Vec<_> = donor_before[..4].iter().map(|&(b, _)| (b, true)).collect();
    assert_eq!(orig_after[..4], with_data);
    assert_eq!(orig_after[4..], orig_before[4..]);
    assert_eq!(donor_after[..4], orig_before[..4]);
    assert_eq!(donor_after[4..], donor_before[4..]);
    // A length of 0 from block 0 moves the whole file, as Linux. The same pairs of blocks swap
    // back, so the first layout comes again.
    assert_eq!(orig.move_extents(&donor, 0, 0, 0), Ok(4));
    assert_eq!(orig.fiemap(0, u64::MAX).unwrap(), first);
    // Blocks without data in both files only swap their extents.
    orig.set_attr(&SetAttr { size: Some(8 * BS as u64), ..SetAttr::default() }).unwrap();
    assert_eq!(orig.move_extents(&donor, 4, 4, 4), Ok(4));
    assert_eq!(blocks(&orig)[4..], donor_before[4..]);
    assert_eq!(blocks(&donor)[4..], orig_before[4..]);
    drop((orig, donor, root, fs));

    let fs = again(&ram);
    let back = read_all(&*fs.root().unwrap().lookup(b"f").unwrap());
    assert_eq!(&back.chunks(BS).map(|c| c[0]).collect::<Vec<_>>(), b"abcd\0\0\0\0");
}

#[test]
fn move_extents_checks_the_files_and_the_range() {
    let (fs, _ram) = open_rw();
    let root = fs.root().unwrap();
    let orig = root.create(b"f", FileType::Regular, 0o644, 0).unwrap();
    orig.write_at(0, &vec![1u8; 4 * BS]).unwrap();
    let donor = root.create(b"d", FileType::Regular, 0o644, 0).unwrap();
    let empty: InodeRef = donor.clone();
    assert_eq!(orig.move_extents(&empty, 0, 0, 4), Err(Errno::EINVAL));
    donor.fallocate(0, 0, 4 * BS as u64).unwrap();
    let dir: InodeRef = root.clone();
    let same: InodeRef = orig.clone();
    let donor: InodeRef = donor;
    assert_eq!(orig.move_extents(&same, 0, 0, 4), Err(Errno::EINVAL));
    assert_eq!(orig.move_extents(&dir, 0, 0, 4), Err(Errno::EINVAL));
    // Blocks of 1 KiB: the starts must have the same place in a page of 4 KiB.
    assert_eq!(orig.move_extents(&donor, 1, 0, 2), Err(Errno::EINVAL));
    assert_eq!(orig.move_extents(&donor, 4, 4, 2), Err(Errno::EINVAL));
    assert_eq!(orig.move_extents(&donor, 1, 1, 2), Ok(2));
    donor.set_attr_flags(flags::EXTENTS | rk_vfs::inode::iflags::APPEND).unwrap();
    assert_eq!(orig.move_extents(&donor, 0, 0, 4), Err(Errno::EPERM));
}

#[test]
fn fallocate_takes_a_run_of_all_the_blocks_after_a_short_hole() {
    let (fs, _ram) = open_rw();
    let root = fs.root().unwrap();
    let a = root.create(b"a", FileType::Regular, 0o644, 0).unwrap();
    a.write_at(0, &vec![1u8; 2 * BS]).unwrap();
    let b = root.create(b"b", FileType::Regular, 0o644, 0).unwrap();
    b.write_at(0, &vec![2u8; BS]).unwrap();
    drop(a);
    root.unlink(b"a").unwrap();
    // The hole of two blocks is too short, so the blocks come from after it.
    let c = root.create(b"c", FileType::Regular, 0o644, 0).unwrap();
    c.fallocate(0, 0, 4 * BS as u64).unwrap();
    assert_eq!(c.fiemap(0, u64::MAX).unwrap().len(), 1);
}

#[test]
fn fsmap_gives_the_metadata_the_free_space_and_the_rest() {
    use fsmap::owner;
    use rk_vfs::inode::fsmap_owner::{FREE, UNKNOWN};
    let (fs, _ram) = open_rw();
    let bs = BS as u64;
    let map: Vec<(u64, u64, u64)> =
        fs.fsmap(0).unwrap().iter().map(|r| (r.physical / bs, r.length / bs, r.owner)).collect();
    let want = [
        (1, 1, owner::FS),
        (2, 1, owner::GDT),
        (3, 1, owner::BLKBM),
        (4, 1, owner::INOBM),
        (5, 8, owner::INODES),
        (13, 7, FREE),
        (20, 3, UNKNOWN),
        (23, 1, FREE),
        (24, 3, UNKNOWN),
        (27, 3, FREE),
        (30, 1, UNKNOWN),
        (31, 9, FREE),
        (40, 1, UNKNOWN),
        (41, 23, FREE),
    ];
    assert_eq!(map, want);
    // A read only mount gives the same map.
    let ro = open(image()).unwrap();
    let ro: Vec<(u64, u64, u64)> =
        ro.fsmap(0).unwrap().iter().map(|r| (r.physical / bs, r.length / bs, r.owner)).collect();
    assert_eq!(ro, want);
    // A new file takes blocks from the free space.
    let file = fs.root().unwrap().create(b"new", FileType::Regular, 0o644, 0).unwrap();
    file.write_at(0, &[1u8; 2 * BS]).unwrap();
    let map = fs.fsmap(0).unwrap();
    let free: u64 = map.iter().filter(|r| r.owner == FREE).map(|r| r.length / bs).sum();
    assert_eq!(free, 43 - 2);
    assert_eq!(map.last().map(|r| r.physical + r.length), Some(64 * bs));
}

/// An image with `bigalloc`: blocks of 1 KiB, clusters of 4 blocks, one group of 256 blocks
/// (64 clusters) and 32 inodes. The first group starts at block 0, so the descriptors are in the
/// block 2. The clusters 0 to 3 have the metadata, and the cluster 4 has the root directory.
fn bigalloc_image() -> Vec<u8> {
    let mut img = Image(vec![0u8; 256 * BS]);
    let sb = 1024;
    img.put32(sb, 32);
    img.put32(sb + 0x4, 256);
    img.put32(sb + 0xc, 59 * 4);
    img.put32(sb + 0x10, 32 - 10);
    img.put32(sb + 0x14, 0);
    img.put32(sb + 0x18, 0);
    img.put32(sb + 0x1c, 2);
    img.put32(sb + 0x20, 256);
    img.put32(sb + 0x24, 64);
    img.put32(sb + 0x28, 32);
    img.put16(sb + 0x38, layout::MAGIC);
    img.put32(sb + 0x4c, 1);
    img.put32(sb + 0x54, 11);
    img.put16(sb + 0x58, 256);
    img.put32(sb + 0x60, layout::incompat::FILETYPE | layout::incompat::EXTENTS);
    img.put32(sb + 0x64, layout::ro_compat::BIGALLOC);
    img.put32(2 * BS, 3);
    img.put32(2 * BS + 4, 4);
    img.put32(2 * BS + 8, INODE_TABLE as u32);
    img.put16(2 * BS + 0xc, 59);
    img.put16(2 * BS + 0xe, 32 - 10);
    img.put16(2 * BS + 0x10, 2);
    // A bit of the block bitmap is a cluster.
    img.0[3 * BS] = 0x1f;
    img.0[3 * BS + 8..4 * BS].fill(0xff);
    img.0[4 * BS] = 0xff;
    img.0[4 * BS + 1] = 0x03;
    img.0[4 * BS + 4..5 * BS].fill(0xff);
    let root = img.inode(2, 0o40755, BS as u32, 2, flags::EXTENTS);
    img.put32(root + 0x1c, 8);
    img.extents(root, &[(0, 1, 16)]);
    img.dir(16, &[(2, 2, b"."), (2, 2, b"..")]);
    img.0
}

fn open_bigalloc(img: Vec<u8>) -> (Result<Arc<Fs>>, Ram) {
    let ram = Ram(Arc::new(SpinLock::new(img)));
    (Fs::open(7, alloc::boxed::Box::new(ram.clone()), false), ram)
}

#[test]
fn bigalloc_gives_and_frees_clusters() {
    use rk_vfs::inode::falloc::{KEEP_SIZE, PUNCH_HOLE};
    let (fs, ram) = open_bigalloc(bigalloc_image());
    let fs = fs.unwrap();
    assert_eq!(fs.sb.desc_block(0), 2);
    // The overhead is the 4 clusters of the metadata.
    assert_eq!((fs.stat().blocks, fs.stat().bfree), (240, 236));
    let file = fs.root().unwrap().create(b"f", FileType::Regular, 0o644, 0).unwrap();
    let (b, cluster) = (BS as u64, 4 * BS as u64);
    // The first block takes a full cluster, and the next block of the cluster uses it.
    file.write_at(0, &vec![b'a'; BS]).unwrap();
    assert_eq!((ram.free().0, file.metadata().blocks), (232, 8));
    file.write_at(b, &vec![b'b'; BS]).unwrap();
    assert_eq!((ram.free().0, file.metadata().blocks), (232, 8));
    let map = file.fiemap(0, u64::MAX).unwrap();
    assert_eq!((map.len(), map[0].length, map[0].physical % cluster), (1, 2 * b, 0));
    // A block in a new logical cluster is at the same offset in its physical cluster.
    file.write_at(6 * b, &vec![b'c'; BS]).unwrap();
    assert_eq!((ram.free().0, file.metadata().blocks), (228, 16));
    let map = file.fiemap(6 * b, b).unwrap();
    assert_eq!(map[0].physical % cluster, 2 * b);
    // A cluster stays while one of its blocks is in use.
    file.set_attr(&SetAttr { size: Some(b), ..SetAttr::default() }).unwrap();
    assert_eq!((ram.free().0, file.metadata().blocks), (232, 8));
    file.fallocate(PUNCH_HOLE | KEEP_SIZE, 0, b).unwrap();
    assert_eq!((ram.free().0, file.metadata().blocks), (236, 0));
    drop((file, fs));

    let fs = again(&ram);
    assert_eq!(fs.stat().bfree, 236);
    let back = read_all(&*fs.root().unwrap().lookup(b"f").unwrap());
    assert!(back.len() == BS && back.iter().all(|&x| x == 0));
}

#[test]
fn bigalloc_fsmap_gives_free_clusters() {
    use rk_vfs::inode::fsmap_owner::FREE;
    let (fs, _ram) = open_bigalloc(bigalloc_image());
    let fs = fs.unwrap();
    let (b, cluster) = (BS as u64, 4 * BS as u64);
    let map = fs.fsmap(0).unwrap();
    let free: Vec<_> = map.iter().filter(|r| r.owner == FREE).collect();
    assert!(free.iter().all(|r| r.physical % cluster == 0 && r.length % cluster == 0));
    assert_eq!(free.iter().map(|r| r.length / b).sum::<u64>(), 236);
    assert_eq!(map.last().map(|r| r.physical + r.length), Some(256 * b));
}

#[test]
fn bigalloc_has_no_move_extents() {
    let (fs, _ram) = open_bigalloc(bigalloc_image());
    let root = fs.unwrap().root().unwrap();
    let orig = root.create(b"o", FileType::Regular, 0o644, 0).unwrap();
    let donor = root.create(b"d", FileType::Regular, 0o644, 0).unwrap();
    orig.write_at(0, &vec![b'o'; BS]).unwrap();
    donor.write_at(0, &vec![b'd'; BS]).unwrap();
    assert_eq!(orig.move_extents(&donor, 0, 0, 1), Err(Errno::EOPNOTSUPP));
}

#[test]
fn bigalloc_collapse_needs_full_clusters() {
    use rk_vfs::inode::falloc::COLLAPSE_RANGE;
    let (fs, ram) = open_bigalloc(bigalloc_image());
    let fs = fs.unwrap();
    let root = fs.root().unwrap();
    let file = root.create(b"f", FileType::Regular, 0o644, 0).unwrap();
    for (i, c) in b"abcdefgh".iter().enumerate() {
        file.write_at((i * BS) as u64, &vec![*c; BS]).unwrap();
    }
    assert_eq!(ram.free().0, 228);
    let b = BS as u64;
    assert_eq!(file.fallocate(COLLAPSE_RANGE, b, b), Err(Errno::EINVAL));
    file.fallocate(COLLAPSE_RANGE, 0, 4 * b).unwrap();
    assert_eq!((file.metadata().size, ram.free().0), (4 * b, 232));
    let firsts: Vec<u8> = read_all(&*file).chunks(BS).map(|c| c[0]).collect();
    assert_eq!(firsts, *b"efgh");
    root.unlink(b"f").unwrap();
    drop((file, root));
    assert_eq!(ram.free().0, 236);
}

#[test]
fn bigalloc_mount_checks_the_superblock() {
    // Without extents the disk is read only, as Linux.
    let mut img = bigalloc_image();
    img[1024 + 0x60] = layout::incompat::FILETYPE as u8;
    assert_eq!(open_bigalloc(img.clone()).0.err(), Some(Errno::EROFS));
    assert!(open(img).is_ok());
    // The clusters per group must agree with the blocks per group.
    let mut img = bigalloc_image();
    img[1024 + 0x24] = 32;
    assert_eq!(open(img).err(), Some(Errno::EINVAL));
    // `first_meta_bg` cannot be past the descriptor blocks, as ext4/025 checks.
    let mut img = bigalloc_image();
    img[1024 + 0x60] |= layout::incompat::META_BG as u8;
    img[1024 + 0x104..1024 + 0x108].copy_from_slice(&842_150_400u32.to_le_bytes());
    assert_eq!(open(img).err(), Some(Errno::EINVAL));
}
