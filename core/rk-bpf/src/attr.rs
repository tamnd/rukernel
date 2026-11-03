//! `union bpf_attr`, the argument of `bpf(2)`, and the rules for its size.
//!
//! A program can give a `union bpf_attr` that is smaller or larger than the one of the kernel.
//! The kernel reads the bytes that it knows, and the bytes after them must be zero, as
//! `bpf_check_uarg_tail_zero` in kernel/bpf/syscall.c of Linux. Each command then checks that the
//! bytes after its last field are zero, as `CHECK_ATTR` of Linux.

use rk_abi::Errno;

/// The size of `union bpf_attr` of Linux 7.3.
pub const BPF_ATTR_SIZE: usize = 168;

/// The size of `struct bpf_common_attr` up to the end of `log_true_size`.
pub const BPF_COMMON_ATTR_SIZE: usize = 20;

/// The largest size that the call accepts, `PAGE_SIZE` of Linux.
const PAGE_SIZE: usize = 4096;

/// The ends of the last fields of the commands, `offsetofend(union bpf_attr, CMD_LAST_FIELD)`.
pub mod last_field {
    /// `BPF_MAP_CREATE`: `excl_prog_hash_size`.
    pub const BPF_MAP_CREATE: usize = 92;
    /// `BPF_MAP_LOOKUP_ELEM`: `flags`.
    pub const BPF_MAP_LOOKUP_ELEM: usize = 32;
    /// `BPF_MAP_UPDATE_ELEM`: `flags`.
    pub const BPF_MAP_UPDATE_ELEM: usize = 32;
    /// `BPF_MAP_DELETE_ELEM`: `key`.
    pub const BPF_MAP_DELETE_ELEM: usize = 16;
    /// `BPF_MAP_GET_NEXT_KEY`: `next_key`.
    pub const BPF_MAP_GET_NEXT_KEY: usize = 24;
    /// `BPF_MAP_FREEZE`: `map_fd`.
    pub const BPF_MAP_FREEZE: usize = 4;
}

/// Checks the size of an argument that a program gives, as `bpf_check_uarg_tail_zero` of Linux.
/// `tail` reads the bytes from `expected` to `actual` of the argument of the program. Gives the
/// count of bytes to copy.
pub fn bpf_check_uarg_tail_zero(
    expected: usize,
    actual: usize,
    tail: impl FnOnce(&mut [u8]) -> Result<(), Errno>,
) -> Result<usize, Errno> {
    if actual > PAGE_SIZE {
        return Err(Errno::E2BIG);
    }
    if actual <= expected {
        return Ok(actual);
    }
    let mut rest = alloc::vec![0u8; actual - expected];
    tail(&mut rest)?;
    if rest.iter().any(|&b| b != 0) {
        return Err(Errno::E2BIG);
    }
    Ok(expected)
}

/// A copy of `union bpf_attr`. The bytes that the program did not give are zero.
#[derive(Clone)]
pub struct BpfAttr(pub [u8; BPF_ATTR_SIZE]);

impl BpfAttr {
    /// An attribute with all bytes zero.
    pub const fn zeroed() -> Self {
        Self([0; BPF_ATTR_SIZE])
    }

    /// Makes an attribute from the first bytes of `bytes`.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut a = Self::zeroed();
        let n = bytes.len().min(BPF_ATTR_SIZE);
        a.0[..n].copy_from_slice(&bytes[..n]);
        a
    }

    /// The `u32` at `offset`.
    pub fn u32(&self, offset: usize) -> u32 {
        u32::from_ne_bytes(self.0[offset..offset + 4].try_into().unwrap_or([0; 4]))
    }

    /// The `u64` at `offset`.
    pub fn u64(&self, offset: usize) -> u64 {
        u64::from_ne_bytes(self.0[offset..offset + 8].try_into().unwrap_or([0; 8]))
    }

    /// Sets the `u32` at `offset`.
    pub fn set_u32(&mut self, offset: usize, v: u32) {
        self.0[offset..offset + 4].copy_from_slice(&v.to_ne_bytes());
    }

    /// Sets the `u64` at `offset`.
    pub fn set_u64(&mut self, offset: usize, v: u64) {
        self.0[offset..offset + 8].copy_from_slice(&v.to_ne_bytes());
    }

    /// Tells if a byte after `end`, the end of the last field of a command, is not zero, as
    /// `CHECK_ATTR` of Linux.
    pub fn check_attr(&self, end: usize) -> bool {
        self.0[end..].iter().any(|&b| b != 0)
    }
}

/// The fields of `BPF_MAP_CREATE`.
pub mod map_create {
    /// `map_type`.
    pub const MAP_TYPE: usize = 0;
    /// `key_size`.
    pub const KEY_SIZE: usize = 4;
    /// `value_size`.
    pub const VALUE_SIZE: usize = 8;
    /// `max_entries`.
    pub const MAX_ENTRIES: usize = 12;
    /// `map_flags`.
    pub const MAP_FLAGS: usize = 16;
    /// `inner_map_fd`.
    pub const INNER_MAP_FD: usize = 20;
    /// `numa_node`.
    pub const NUMA_NODE: usize = 24;
    /// `map_name`, 16 bytes.
    pub const MAP_NAME: usize = 28;
    /// `map_ifindex`.
    pub const MAP_IFINDEX: usize = 44;
    /// `btf_fd`.
    pub const BTF_FD: usize = 48;
    /// `btf_key_type_id`.
    pub const BTF_KEY_TYPE_ID: usize = 52;
    /// `btf_value_type_id`.
    pub const BTF_VALUE_TYPE_ID: usize = 56;
    /// `btf_vmlinux_value_type_id`.
    pub const BTF_VMLINUX_VALUE_TYPE_ID: usize = 60;
    /// `map_extra`.
    pub const MAP_EXTRA: usize = 64;
    /// `value_type_btf_obj_fd`.
    pub const VALUE_TYPE_BTF_OBJ_FD: usize = 72;
    /// `map_token_fd`.
    pub const MAP_TOKEN_FD: usize = 76;
    /// `excl_prog_hash`.
    pub const EXCL_PROG_HASH: usize = 80;
    /// `excl_prog_hash_size`.
    pub const EXCL_PROG_HASH_SIZE: usize = 88;
}

/// The fields of the `BPF_MAP_*_ELEM` commands and `BPF_MAP_FREEZE`.
pub mod map_elem {
    /// `map_fd`.
    pub const MAP_FD: usize = 0;
    /// `key`.
    pub const KEY: usize = 8;
    /// `value`, and `next_key` for `BPF_MAP_GET_NEXT_KEY`.
    pub const VALUE: usize = 16;
    /// `flags`.
    pub const FLAGS: usize = 24;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_small_argument_is_copied_whole() {
        assert_eq!(bpf_check_uarg_tail_zero(BPF_ATTR_SIZE, 72, |_| unreachable!()), Ok(72));
    }

    #[test]
    fn a_large_argument_needs_a_zero_tail() {
        assert_eq!(bpf_check_uarg_tail_zero(BPF_ATTR_SIZE, 200, |_| Ok(())), Ok(BPF_ATTR_SIZE));
        let r = bpf_check_uarg_tail_zero(BPF_ATTR_SIZE, 200, |b| {
            b[3] = 1;
            Ok(())
        });
        assert_eq!(r, Err(Errno::E2BIG));
        assert_eq!(bpf_check_uarg_tail_zero(BPF_ATTR_SIZE, 4097, |_| Ok(())), Err(Errno::E2BIG));
    }

    #[test]
    fn check_attr_finds_bytes_after_the_last_field() {
        let mut a = BpfAttr::zeroed();
        a.set_u64(map_elem::FLAGS, 1);
        assert!(!a.check_attr(last_field::BPF_MAP_LOOKUP_ELEM));
        assert!(a.check_attr(last_field::BPF_MAP_DELETE_ELEM));
    }
}
