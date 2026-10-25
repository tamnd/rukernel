//! Tests on a small ext4 image that the test makes byte by byte. The image has blocks of 1 KiB,
//! one group of 64 blocks and 32 inodes of 256 bytes.

use super::*;
use layout::flags;
use rk_vfs::{FileType, Inode, Timespec};

const BS: usize = 1024;
const INODE_TABLE: usize = 5;

/// A disk in memory.
struct Ram(Vec<u8>);

impl Disk for Ram {
    fn read(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let at = offset as usize;
        let data = self.0.get(at..at + buf.len()).ok_or(Errno::EIO)?;
        buf.copy_from_slice(data);
        Ok(())
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
    Fs::open(7, alloc::boxed::Box::new(Ram(img)))
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
}
