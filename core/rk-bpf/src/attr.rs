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
    /// `BPF_PROG_LOAD`: `keyring_id`.
    pub const BPF_PROG_LOAD: usize = 168;
    /// `BPF_OBJ_PIN` and `BPF_OBJ_GET`: `path_fd`.
    pub const BPF_OBJ: usize = 20;
    /// `BPF_*_GET_NEXT_ID`: `next_id`.
    pub const BPF_OBJ_GET_NEXT_ID: usize = 8;
    /// `BPF_PROG_GET_FD_BY_ID`: `prog_id`.
    pub const BPF_PROG_GET_FD_BY_ID: usize = 4;
    /// `BPF_MAP_GET_FD_BY_ID`: `open_flags`.
    pub const BPF_MAP_GET_FD_BY_ID: usize = 12;
    /// `BPF_LINK_GET_FD_BY_ID`: `link_id`.
    pub const BPF_LINK_GET_FD_BY_ID: usize = 4;
    /// `BPF_OBJ_GET_INFO_BY_FD`: `info.info`.
    pub const BPF_OBJ_GET_INFO_BY_FD: usize = 16;
    /// `BPF_PROG_ATTACH`: `expected_revision`.
    pub const BPF_PROG_ATTACH: usize = 32;
    /// `BPF_PROG_DETACH`: `expected_revision`.
    pub const BPF_PROG_DETACH: usize = 32;
    /// `BPF_PROG_QUERY`: `query.revision`.
    pub const BPF_PROG_QUERY: usize = 64;
    /// `BPF_LINK_CREATE`: `link_create.uprobe_multi.path_fd`.
    pub const BPF_LINK_CREATE: usize = 64;
    /// `BPF_LINK_UPDATE`: `link_update.old_prog_fd`.
    pub const BPF_LINK_UPDATE: usize = 16;
    /// `BPF_LINK_DETACH`: `link_detach.link_fd`.
    pub const BPF_LINK_DETACH: usize = 4;
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

/// The fields of `BPF_OBJ_PIN` and `BPF_OBJ_GET`.
pub mod obj {
    /// `pathname`.
    pub const PATHNAME: usize = 0;
    /// `bpf_fd`.
    pub const BPF_FD: usize = 8;
    /// `file_flags`.
    pub const FILE_FLAGS: usize = 12;
    /// `path_fd`.
    pub const PATH_FD: usize = 16;
}

/// The fields of the `BPF_*_GET_NEXT_ID` and `BPF_*_GET_FD_BY_ID` commands.
pub mod get_id {
    /// `start_id`, `prog_id`, `map_id` or `link_id`.
    pub const START_ID: usize = 0;
    /// `next_id`.
    pub const NEXT_ID: usize = 4;
    /// `open_flags`.
    pub const OPEN_FLAGS: usize = 8;
}

/// The fields of `BPF_OBJ_GET_INFO_BY_FD`, `info`.
pub mod info {
    /// `bpf_fd`.
    pub const BPF_FD: usize = 0;
    /// `info_len`.
    pub const INFO_LEN: usize = 4;
    /// `info`.
    pub const INFO: usize = 8;
}

/// The fields of `BPF_PROG_ATTACH` and `BPF_PROG_DETACH`.
pub mod prog_attach {
    /// `target_fd`.
    pub const TARGET_FD: usize = 0;
    /// `attach_bpf_fd`.
    pub const ATTACH_BPF_FD: usize = 4;
    /// `attach_type`.
    pub const ATTACH_TYPE: usize = 8;
    /// `attach_flags`.
    pub const ATTACH_FLAGS: usize = 12;
    /// `replace_bpf_fd`.
    pub const REPLACE_BPF_FD: usize = 16;
    /// `relative_fd` or `relative_id`.
    pub const RELATIVE_FD: usize = 20;
    /// `expected_revision`.
    pub const EXPECTED_REVISION: usize = 24;
}

/// The fields of `BPF_LINK_CREATE`, `link_create`.
pub mod link_create {
    /// `prog_fd`.
    pub const PROG_FD: usize = 0;
    /// `target_fd`.
    pub const TARGET_FD: usize = 4;
    /// `attach_type`.
    pub const ATTACH_TYPE: usize = 8;
    /// `flags`.
    pub const FLAGS: usize = 12;
    /// `cgroup.relative_fd` or `cgroup.relative_id`.
    pub const RELATIVE_FD: usize = 16;
    /// `cgroup.expected_revision`.
    pub const EXPECTED_REVISION: usize = 24;
}

/// The fields of `BPF_LINK_UPDATE` and `BPF_LINK_DETACH`.
pub mod link_update {
    /// `link_fd`.
    pub const LINK_FD: usize = 0;
    /// `new_prog_fd`.
    pub const NEW_PROG_FD: usize = 4;
    /// `flags`.
    pub const FLAGS: usize = 8;
    /// `old_prog_fd`.
    pub const OLD_PROG_FD: usize = 12;
}

/// The fields of `BPF_PROG_LOAD`.
pub mod prog_load {
    /// `prog_type`.
    pub const PROG_TYPE: usize = 0;
    /// `insn_cnt`.
    pub const INSN_CNT: usize = 4;
    /// `insns`.
    pub const INSNS: usize = 8;
    /// `license`.
    pub const LICENSE: usize = 16;
    /// `log_level`.
    pub const LOG_LEVEL: usize = 24;
    /// `log_size`.
    pub const LOG_SIZE: usize = 28;
    /// `log_buf`.
    pub const LOG_BUF: usize = 32;
    /// `kern_version`.
    pub const KERN_VERSION: usize = 40;
    /// `prog_flags`.
    pub const PROG_FLAGS: usize = 44;
    /// `prog_name`, 16 bytes.
    pub const PROG_NAME: usize = 48;
    /// `prog_ifindex`.
    pub const PROG_IFINDEX: usize = 64;
    /// `expected_attach_type`.
    pub const EXPECTED_ATTACH_TYPE: usize = 68;
    /// `prog_btf_fd`.
    pub const PROG_BTF_FD: usize = 72;
    /// `func_info_rec_size`.
    pub const FUNC_INFO_REC_SIZE: usize = 76;
    /// `func_info`.
    pub const FUNC_INFO: usize = 80;
    /// `func_info_cnt`.
    pub const FUNC_INFO_CNT: usize = 88;
    /// `line_info_rec_size`.
    pub const LINE_INFO_REC_SIZE: usize = 92;
    /// `line_info`.
    pub const LINE_INFO: usize = 96;
    /// `line_info_cnt`.
    pub const LINE_INFO_CNT: usize = 104;
    /// `attach_btf_id`.
    pub const ATTACH_BTF_ID: usize = 108;
    /// `attach_prog_fd`.
    pub const ATTACH_PROG_FD: usize = 112;
    /// `core_relo_cnt`.
    pub const CORE_RELO_CNT: usize = 116;
    /// `fd_array`.
    pub const FD_ARRAY: usize = 120;
    /// `core_relos`.
    pub const CORE_RELOS: usize = 128;
    /// `core_relo_rec_size`.
    pub const CORE_RELO_REC_SIZE: usize = 136;
    /// `log_true_size`.
    pub const LOG_TRUE_SIZE: usize = 140;
    /// `prog_token_fd`.
    pub const PROG_TOKEN_FD: usize = 144;
    /// `fd_array_cnt`.
    pub const FD_ARRAY_CNT: usize = 148;
    /// `signature`.
    pub const SIGNATURE: usize = 152;
    /// `signature_size`.
    pub const SIGNATURE_SIZE: usize = 160;
    /// `keyring_id`.
    pub const KEYRING_ID: usize = 164;
}

/// The fields of `struct bpf_common_attr`.
pub mod common {
    /// `log_buf`.
    pub const LOG_BUF: usize = 0;
    /// `log_size`.
    pub const LOG_SIZE: usize = 8;
    /// `log_level`.
    pub const LOG_LEVEL: usize = 12;
    /// `log_true_size`.
    pub const LOG_TRUE_SIZE: usize = 16;
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
