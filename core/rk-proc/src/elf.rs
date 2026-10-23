//! The headers of an ELF executable file.
//!
//! The loader reads the file header and the program headers, per the System V ABI and
//! fs/binfmt_elf.c of Linux. The kernel needs only the segments to load, the program interpreter,
//! the entry point and the place of the program headers for the auxiliary vector.

use alloc::vec::Vec;
use rk_abi::Errno;
use rk_abi::native::elf::{
    EI_CLASS, EI_DATA, EI_VERSION, ELFCLASS64, ELFDATA2LSB, ET_DYN, ET_EXEC, EV_CURRENT, PF_R,
    PF_W, PF_X, PT_GNU_STACK, PT_INTERP, PT_LOAD, PT_PHDR,
};

/// The size of the file header of a 64 bit ELF file.
pub const EHDR_SIZE: usize = 64;
/// The size of one program header of a 64 bit ELF file.
pub const PHDR_SIZE: usize = 56;
/// The most program headers that the loader reads. Linux has the same limit: 64 KiB of headers.
pub const MAX_PHNUM: usize = 65536 / PHDR_SIZE;
/// The longest path of a program interpreter. Linux uses `PATH_MAX`.
pub const MAX_INTERP: usize = 4096;

/// The type of an ELF file that the kernel can run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ElfType {
    /// `ET_EXEC`: the file runs at the addresses in its headers.
    Exec,
    /// `ET_DYN`: a position independent executable or a shared object. The loader chooses a base.
    Dyn,
}

/// The access of a segment, from `p_flags`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SegmentFlags {
    /// `PF_R`.
    pub read: bool,
    /// `PF_W`.
    pub write: bool,
    /// `PF_X`.
    pub exec: bool,
}

/// A `PT_LOAD` segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Segment {
    /// The offset of the data in the file.
    pub offset: u64,
    /// The virtual address, before the load bias.
    pub vaddr: u64,
    /// The bytes that come from the file.
    pub filesz: u64,
    /// The bytes in memory. The bytes after `filesz` are zero.
    pub memsz: u64,
    /// The access.
    pub flags: SegmentFlags,
}

/// The file header and the program headers of an ELF file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ElfHeader {
    /// The type.
    pub kind: ElfType,
    /// The entry point, before the load bias.
    pub entry: u64,
    /// The offset of the program headers in the file.
    pub phoff: u64,
    /// The number of program headers.
    pub phnum: u16,
    /// The virtual address of the program headers from `PT_PHDR`, before the load bias.
    pub phdr: Option<u64>,
    /// The `PT_LOAD` segments, in the order of the file.
    pub segments: Vec<Segment>,
    /// The offset and the size of the path of the program interpreter, from `PT_INTERP`.
    pub interp: Option<(u64, u64)>,
    /// `PT_GNU_STACK` asks for an executable stack.
    pub exec_stack: bool,
}

fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(v)
}

/// Tells if `data` starts with the ELF magic number. `execve` gives `ENOEXEC` for a file without
/// it.
pub fn is_elf(data: &[u8]) -> bool {
    data.starts_with(b"\x7fELF")
}

/// Reads the file header in `ehdr`. Gives the offset and the size of the program headers. The
/// file must be a 64 bit little endian file for the machine `machine`.
///
/// # Errors
///
/// Gives `ENOEXEC` if the file is not an executable or a shared object for this machine.
pub fn parse_ehdr(ehdr: &[u8], machine: u16) -> Result<(u64, usize), Errno> {
    if ehdr.len() < EHDR_SIZE || !is_elf(ehdr) {
        return Err(Errno::ENOEXEC);
    }
    let ok_ident = u32::from(ehdr[EI_CLASS as usize]) == ELFCLASS64
        && u32::from(ehdr[EI_DATA as usize]) == ELFDATA2LSB
        && u32::from(ehdr[EI_VERSION as usize]) == EV_CURRENT;
    let kind = u32::from(u16_at(ehdr, 16));
    if !ok_ident || (kind != ET_EXEC && kind != ET_DYN) || u16_at(ehdr, 18) != machine {
        return Err(Errno::ENOEXEC);
    }
    let phoff = u64_at(ehdr, 32);
    let phentsize = usize::from(u16_at(ehdr, 54));
    let phnum = usize::from(u16_at(ehdr, 56));
    if phentsize != PHDR_SIZE || phnum == 0 || phnum > MAX_PHNUM {
        return Err(Errno::ENOEXEC);
    }
    Ok((phoff, phnum * PHDR_SIZE))
}

/// Reads the file header in `ehdr` and the program headers in `phdrs`.
///
/// # Errors
///
/// Gives `ENOEXEC` for a header that is not correct, and `EINVAL` for a segment that is not
/// correct, as Linux does.
pub fn parse(ehdr: &[u8], phdrs: &[u8], machine: u16) -> Result<ElfHeader, Errno> {
    let (phoff, size) = parse_ehdr(ehdr, machine)?;
    if phdrs.len() != size {
        return Err(Errno::ENOEXEC);
    }
    let kind = if u32::from(u16_at(ehdr, 16)) == ET_EXEC { ElfType::Exec } else { ElfType::Dyn };
    let mut header = ElfHeader {
        kind,
        entry: u64_at(ehdr, 24),
        phoff,
        phnum: u16_at(ehdr, 56),
        phdr: None,
        segments: Vec::new(),
        interp: None,
        exec_stack: false,
    };
    for ph in phdrs.as_chunks::<PHDR_SIZE>().0 {
        let p_type = u32_at(ph, 0);
        let p_flags = u32_at(ph, 4);
        let offset = u64_at(ph, 8);
        let vaddr = u64_at(ph, 16);
        let filesz = u64_at(ph, 32);
        let memsz = u64_at(ph, 40);
        let align = u64_at(ph, 48);
        match p_type {
            PT_LOAD => {
                let page = crate::PAGE_SIZE as u64;
                // The offset and the address must be the same modulo the page size, so that the
                // file page maps at the address.
                if filesz > memsz
                    || vaddr % page != offset % page
                    || (align > 1 && vaddr % align != offset % align)
                    || vaddr.checked_add(memsz).is_none()
                    || offset.checked_add(filesz).is_none()
                {
                    return Err(Errno::EINVAL);
                }
                let flags = SegmentFlags {
                    read: p_flags & PF_R != 0,
                    write: p_flags & PF_W != 0,
                    exec: p_flags & PF_X != 0,
                };
                header.segments.push(Segment { offset, vaddr, filesz, memsz, flags });
            }
            PT_INTERP => {
                if header.interp.is_some() || filesz < 2 || filesz > MAX_INTERP as u64 {
                    return Err(Errno::ENOEXEC);
                }
                header.interp = Some((offset, filesz));
            }
            PT_PHDR => header.phdr = Some(vaddr),
            PT_GNU_STACK => header.exec_stack = p_flags & PF_X != 0,
            _ => {}
        }
    }
    if header.segments.is_empty() {
        return Err(Errno::ENOEXEC);
    }
    Ok(header)
}

impl ElfHeader {
    /// The lowest and the highest virtual address of the loaded segments, before the load bias.
    /// The low address is page aligned down and the high address is page aligned up.
    pub fn span(&self) -> (u64, u64) {
        let page = crate::PAGE_SIZE as u64;
        let low = self.segments.iter().map(|s| s.vaddr).min().unwrap_or(0);
        let high = self.segments.iter().map(|s| s.vaddr + s.memsz).max().unwrap_or(0);
        (low / page * page, high.div_ceil(page) * page)
    }

    /// The virtual address of the program headers, before the load bias. It comes from `PT_PHDR`,
    /// or else from the segment that contains the headers in the file.
    pub fn phdr_addr(&self) -> Option<u64> {
        if let Some(addr) = self.phdr {
            return Some(addr);
        }
        let size = u64::from(self.phnum) * PHDR_SIZE as u64;
        self.segments
            .iter()
            .find(|s| s.offset <= self.phoff && self.phoff + size <= s.offset + s.filesz)
            .map(|s| s.vaddr + (self.phoff - s.offset))
    }
}
