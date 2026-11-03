//! The maps, `struct bpf_map` of include/linux/bpf.h of Linux.
//!
//! A map has a type, a key size, a value size and a largest count of elements. Each type has
//! its operations, as `struct bpf_map_ops` of Linux. The element of a per CPU map has one value
//! for each CPU, and the system calls copy all of them, each value rounded up to 8 bytes, as
//! `bpf_map_value_size` of kernel/bpf/syscall.c.

pub mod arraymap;
pub mod hashtab;
pub mod lpm_trie;

use crate::uapi::BPF_OBJ_NAME_LEN;
use crate::uapi::elem::{BPF_F_ALL_CPUS, BPF_F_CPU, BPF_F_LOCK};
use crate::uapi::flags::{BPF_F_RDONLY_PROG, BPF_F_WRONLY_PROG};
use crate::uapi::map_type::*;
use crate::value::MapValue;
use alloc::boxed::Box;
use alloc::format;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use rk_abi::Errno;
use rk_frame::sync::SpinLock;

/// The result of a map operation.
pub type Result<T> = core::result::Result<T, Errno>;

/// One element of a map: one value, or one value for each CPU in a per CPU map.
pub struct Elem {
    vals: Vec<MapValue>,
}

impl Elem {
    /// An element with `n` values of `size` bytes, all zero.
    pub fn zeroed(n: usize, size: usize) -> Result<Self> {
        let mut vals = Vec::new();
        vals.try_reserve_exact(n).map_err(|_| Errno::ENOMEM)?;
        for _ in 0..n {
            vals.push(MapValue::zeroed(size)?);
        }
        Ok(Self { vals })
    }

    /// The value of the CPU `cpu`. A map that is not per CPU has one value.
    pub fn value(&self, cpu: usize) -> &MapValue {
        &self.vals[cpu.min(self.vals.len() - 1)]
    }
}

/// What a map needs to know of the machine.
#[derive(Clone, Copy, Debug)]
pub struct MapEnv {
    /// The number of possible CPUs, `num_possible_cpus()` of Linux.
    pub nr_cpus: usize,
    /// The CPU that runs the caller.
    pub cpu: usize,
}

/// The attributes of a new map, from `union bpf_attr`.
#[derive(Clone, Copy, Debug, Default)]
pub struct MapAttr {
    /// `map_type`.
    pub map_type: u32,
    /// `key_size`.
    pub key_size: u32,
    /// `value_size`.
    pub value_size: u32,
    /// `max_entries`.
    pub max_entries: u32,
    /// `map_flags`.
    pub map_flags: u32,
    /// `numa_node`, used only with `BPF_F_NUMA_NODE`.
    pub numa_node: u32,
}

/// The operations of a type of map, as `struct bpf_map_ops` of Linux.
pub trait BpfMapOps: Send + Sync {
    /// Finds the element of `key`, as `map_lookup_elem`.
    fn map_lookup_elem(&self, key: &[u8]) -> Option<Arc<Elem>>;
    /// Adds or changes the element of `key`, as `map_update_elem`. `onallcpus` tells that
    /// `value` has the values of all CPUs, as for a system call on a per CPU map.
    fn map_update_elem(
        &self,
        key: &[u8],
        value: &[u8],
        flags: u64,
        onallcpus: bool,
        env: MapEnv,
    ) -> Result<()>;
    /// Removes the element of `key`, as `map_delete_elem`.
    fn map_delete_elem(&self, key: &[u8]) -> Result<()>;
    /// Writes the key after `key` to `next`, as `map_get_next_key`.
    fn map_get_next_key(&self, key: Option<&[u8]>, next: &mut [u8]) -> Result<()>;
    /// The bytes that the map uses, as `map_mem_usage`.
    fn map_mem_usage(&self) -> u64;
}

/// A map, `struct bpf_map` of Linux.
pub struct BpfMap {
    /// `map_type`.
    pub map_type: u32,
    /// `key_size`.
    pub key_size: u32,
    /// `value_size`.
    pub value_size: u32,
    /// `max_entries`.
    pub max_entries: u32,
    /// `map_flags`.
    pub map_flags: u32,
    /// `map_extra`.
    pub map_extra: u64,
    /// The ID, which `BPF_MAP_GET_FD_BY_ID` uses.
    pub id: u32,
    /// The name, with zero bytes at the end.
    pub name: [u8; BPF_OBJ_NAME_LEN],
    /// The number of possible CPUs when the map was made.
    pub nr_cpus: usize,
    /// The system calls cannot change the map, after `BPF_MAP_FREEZE`.
    pub frozen: AtomicBool,
    /// The lock of `BPF_MAP_FREEZE`, `freeze_mutex` of Linux.
    pub freeze_mutex: SpinLock<()>,
    /// The count of the system calls that write the map now, `writecnt` of Linux.
    pub writecnt: AtomicU32,
    /// The operations of the type.
    pub ops: Box<dyn BpfMapOps>,
}

/// The next map ID. Linux uses `idr_alloc_cyclic` from 1.
static NEXT_ID: AtomicU32 = AtomicU32::new(1);

/// Tells if the map type has one value for each CPU, `bpf_map_is_percpu_map` of Linux.
pub fn bpf_map_is_percpu_map(map_type: u32) -> bool {
    matches!(map_type, BPF_MAP_TYPE_PERCPU_HASH | BPF_MAP_TYPE_PERCPU_ARRAY)
}

/// Tells if the flags of the access of programs are valid, `bpf_map_flags_access_ok` of Linux.
pub fn bpf_map_flags_access_ok(flags: u32) -> bool {
    flags & (BPF_F_RDONLY_PROG | BPF_F_WRONLY_PROG) != BPF_F_RDONLY_PROG | BPF_F_WRONLY_PROG
}

/// Rounds `n` up to a multiple of 8.
pub(crate) fn round_up8(n: u32) -> usize {
    (n as usize).div_ceil(8) * 8
}

/// Tells if rukernel has the map type, as a `bpf_map_types` entry of Linux that is not NULL.
pub fn bpf_map_type_known(map_type: u32) -> bool {
    matches!(
        map_type,
        BPF_MAP_TYPE_HASH
            | BPF_MAP_TYPE_PERCPU_HASH
            | BPF_MAP_TYPE_ARRAY
            | BPF_MAP_TYPE_PERCPU_ARRAY
            | BPF_MAP_TYPE_LPM_TRIE
    )
}

/// Checks the attributes of a new map, as `map_alloc_check` of the type. The type is known.
pub fn map_alloc_check(attr: &MapAttr) -> Result<()> {
    match attr.map_type {
        BPF_MAP_TYPE_HASH | BPF_MAP_TYPE_PERCPU_HASH => hashtab::htab_map_alloc_check(attr),
        BPF_MAP_TYPE_ARRAY | BPF_MAP_TYPE_PERCPU_ARRAY => arraymap::array_map_alloc_check(attr),
        // The trie has no `map_alloc_check`: `trie_alloc` checks the attributes.
        _ => Ok(()),
    }
}

/// Makes a map, as `map_alloc` of the type. `avail` is the count of bytes that the map can
/// take, and a larger map gives `ENOMEM`.
pub fn map_alloc(attr: &MapAttr, nr_cpus: usize, avail: u64) -> Result<Box<dyn BpfMapOps>> {
    match attr.map_type {
        BPF_MAP_TYPE_HASH | BPF_MAP_TYPE_PERCPU_HASH => {
            Ok(Box::new(hashtab::BpfHtab::alloc(attr, nr_cpus, avail)?))
        }
        BPF_MAP_TYPE_ARRAY | BPF_MAP_TYPE_PERCPU_ARRAY => {
            Ok(Box::new(arraymap::BpfArray::alloc(attr, nr_cpus, avail)?))
        }
        BPF_MAP_TYPE_LPM_TRIE => Ok(Box::new(lpm_trie::LpmTrie::alloc(attr, avail)?)),
        _ => Err(Errno::EINVAL),
    }
}

impl BpfMap {
    /// Makes a map with the operations `ops` and a new ID.
    pub fn new(
        attr: &MapAttr,
        name: [u8; BPF_OBJ_NAME_LEN],
        nr_cpus: usize,
        ops: Box<dyn BpfMapOps>,
    ) -> Self {
        Self {
            map_type: attr.map_type,
            key_size: attr.key_size,
            value_size: attr.value_size,
            max_entries: attr.max_entries,
            map_flags: attr.map_flags,
            map_extra: 0,
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            name,
            nr_cpus,
            frozen: AtomicBool::new(false),
            freeze_mutex: SpinLock::new(()),
            writecnt: AtomicU32::new(0),
            ops,
        }
    }

    /// Tells if the map has one value for each CPU.
    pub fn is_percpu(&self) -> bool {
        bpf_map_is_percpu_map(self.map_type)
    }

    /// Checks the flags of a lookup or an update from a system call, as
    /// `bpf_map_check_op_flags` of include/linux/bpf.h.
    pub fn check_op_flags(&self, flags: u64, allowed: u64) -> Result<()> {
        if (flags as u32 as u64) & !allowed != 0 {
            return Err(Errno::EINVAL);
        }
        // No map of rukernel has a `bpf_spin_lock` in its value, because there is no BTF.
        if flags & BPF_F_LOCK != 0 {
            return Err(Errno::EINVAL);
        }
        if flags & BPF_F_CPU == 0 && flags >> 32 != 0 {
            return Err(Errno::EINVAL);
        }
        if flags & (BPF_F_CPU | BPF_F_ALL_CPUS) != 0 {
            if !self.is_percpu() || (flags & BPF_F_CPU != 0 && flags & BPF_F_ALL_CPUS != 0) {
                return Err(Errno::EINVAL);
            }
            if flags & BPF_F_CPU != 0 && (flags >> 32) as usize >= self.nr_cpus {
                return Err(Errno::ERANGE);
            }
        }
        Ok(())
    }

    /// The size of the value buffer of a system call, `bpf_map_value_size` of Linux.
    pub fn bpf_map_value_size(&self, flags: u64) -> usize {
        if flags & (BPF_F_CPU | BPF_F_ALL_CPUS) != 0 {
            self.value_size as usize
        } else if self.is_percpu() {
            round_up8(self.value_size) * self.nr_cpus
        } else {
            self.value_size as usize
        }
    }

    /// Copies the value of `key` to `out` for a system call, as `bpf_map_copy_value` of Linux.
    pub fn bpf_map_copy_value(&self, key: &[u8], out: &mut [u8], flags: u64) -> Result<()> {
        let elem = self.ops.map_lookup_elem(key).ok_or(Errno::ENOENT)?;
        if !self.is_percpu() {
            elem.value(0).read(0, &mut out[..self.value_size as usize]);
        } else if flags & BPF_F_CPU != 0 {
            elem.value((flags >> 32) as usize).read(0, &mut out[..self.value_size as usize]);
        } else {
            // As `bpf_percpu_array_copy` and `bpf_percpu_hash_copy`: each CPU has its value
            // rounded up to 8 bytes.
            let size = round_up8(self.value_size);
            for (cpu, chunk) in out.chunks_mut(size).enumerate().take(self.nr_cpus) {
                elem.value(cpu).read(0, chunk);
            }
        }
        Ok(())
    }

    /// Changes the value of `key` for a system call, as `bpf_map_update_value` of Linux.
    pub fn bpf_map_update_value(
        &self,
        key: &[u8],
        value: &[u8],
        flags: u64,
        env: MapEnv,
    ) -> Result<()> {
        self.ops.map_update_elem(key, value, flags, self.is_percpu(), env)
    }

    /// The text of `/proc/PID/fdinfo` after the common lines, as `bpf_map_show_fdinfo` of Linux.
    pub fn show_fdinfo(&self) -> Vec<u8> {
        format!(
            "map_type:\t{}\nkey_size:\t{}\nvalue_size:\t{}\nmax_entries:\t{}\nmap_flags:\t{:#x}\n\
             map_extra:\t{:#x}\nmemlock:\t{}\nmap_id:\t{}\nfrozen:\t{}\n",
            self.map_type,
            self.key_size,
            self.value_size,
            self.max_entries,
            self.map_flags,
            self.map_extra,
            self.ops.map_mem_usage(),
            self.id,
            u32::from(self.frozen.load(Ordering::Relaxed)),
        )
        .into_bytes()
    }
}

/// Copies the values of a system call or of a program to an element, as `pcpu_copy_value` in
/// kernel/bpf/hashtab.c of Linux. A map that is not per CPU has one value.
pub(crate) fn pcpu_copy_value(
    elem: &Elem,
    value_size: u32,
    value: &[u8],
    onallcpus: bool,
    flags: u64,
    cpu: usize,
) {
    let n = value_size as usize;
    if elem.vals.len() == 1 {
        elem.vals[0].write(0, &value[..n]);
    } else if !onallcpus {
        elem.value(cpu).write(0, &value[..n]);
    } else if flags & BPF_F_CPU != 0 {
        elem.value((flags >> 32) as usize).write(0, &value[..n]);
    } else {
        let size = round_up8(value_size);
        for (i, v) in elem.vals.iter().enumerate() {
            let off = if flags & BPF_F_ALL_CPUS != 0 { 0 } else { i * size };
            v.write(0, &value[off..off + n]);
        }
    }
}

/// Makes the element of a new key, as `pcpu_init_value` in kernel/bpf/hashtab.c of Linux. When
/// the caller does not give the values of all CPUs, the values of the other CPUs are zero.
pub(crate) fn pcpu_init_value(
    n: usize,
    value_size: u32,
    value: &[u8],
    onallcpus: bool,
    flags: u64,
    cpu: usize,
) -> Result<Elem> {
    let elem = Elem::zeroed(n, round_up8(value_size))?;
    if n > 1 && (!onallcpus || flags & BPF_F_CPU != 0) {
        let init_cpu = if flags & BPF_F_CPU != 0 { (flags >> 32) as usize } else { cpu };
        elem.value(init_cpu).write(0, &value[..value_size as usize]);
    } else {
        pcpu_copy_value(&elem, value_size, value, onallcpus, flags, cpu);
    }
    Ok(elem)
}

/// Copies the name of a map or a program, as `bpf_obj_name_cpy` of Linux: only letters, digits,
/// `_` and `.`, with a zero byte in the field.
pub fn bpf_obj_name_cpy(src: &[u8]) -> Result<[u8; BPF_OBJ_NAME_LEN]> {
    let mut dst = [0u8; BPF_OBJ_NAME_LEN];
    for (i, &c) in src.iter().take(BPF_OBJ_NAME_LEN).enumerate() {
        if c == 0 {
            return Ok(dst);
        }
        if !c.is_ascii_alphanumeric() && c != b'_' && c != b'.' {
            return Err(Errno::EINVAL);
        }
        dst[i] = c;
    }
    Err(Errno::EINVAL)
}
