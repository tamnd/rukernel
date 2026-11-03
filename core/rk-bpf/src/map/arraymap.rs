//! The array maps, kernel/bpf/arraymap.c of Linux: `BPF_MAP_TYPE_ARRAY` and
//! `BPF_MAP_TYPE_PERCPU_ARRAY`.
//!
//! The key is a `u32` index. All elements exist from the start and have zero values.

use super::hashtab::PCPU_MIN_UNIT_SIZE;
use super::{
    BpfMapOps, Elem, MapAttr, MapEnv, Result, bpf_map_flags_access_ok, pcpu_copy_value, round_up8,
};
use crate::uapi::elem::{BPF_EXIST, BPF_F_ALL_CPUS, BPF_F_LOCK, BPF_NOEXIST};
use crate::uapi::flags::*;
use crate::uapi::map_type::{BPF_MAP_TYPE_ARRAY, BPF_MAP_TYPE_PERCPU_ARRAY};
use alloc::sync::Arc;
use alloc::vec::Vec;
use rk_abi::Errno;

/// The flags that an array map accepts, `ARRAY_CREATE_FLAG_MASK` of Linux.
const ARRAY_CREATE_FLAG_MASK: u32 =
    BPF_F_NUMA_NODE | BPF_F_MMAPABLE | BPF_F_ACCESS_MASK | BPF_F_PRESERVE_ELEMS | BPF_F_INNER_MAP;

/// The memory of one element in rukernel, in addition to the values.
const ELEM_OVERHEAD: u64 = 64;

/// Checks the attributes of a new array map, `array_map_alloc_check` of Linux.
pub fn array_map_alloc_check(attr: &MapAttr) -> Result<()> {
    let percpu = attr.map_type == BPF_MAP_TYPE_PERCPU_ARRAY;
    let numa = attr.map_flags & BPF_F_NUMA_NODE != 0;
    if attr.max_entries == 0
        || attr.key_size != 4
        || attr.value_size == 0
        || attr.map_flags & !ARRAY_CREATE_FLAG_MASK != 0
        || !bpf_map_flags_access_ok(attr.map_flags)
        || (percpu && numa)
    {
        return Err(Errno::EINVAL);
    }
    if attr.map_type != BPF_MAP_TYPE_ARRAY
        && attr.map_flags & (BPF_F_MMAPABLE | BPF_F_INNER_MAP) != 0
    {
        return Err(Errno::EINVAL);
    }
    // rukernel has no perf event array, which is the only map with `BPF_F_PRESERVE_ELEMS`.
    if attr.map_flags & BPF_F_PRESERVE_ELEMS != 0 {
        return Err(Errno::EINVAL);
    }
    if attr.value_size > i32::MAX as u32 {
        return Err(Errno::E2BIG);
    }
    if percpu && round_up8(attr.value_size) > PCPU_MIN_UNIT_SIZE {
        return Err(Errno::E2BIG);
    }
    Ok(())
}

/// An array map, `struct bpf_array` of Linux.
pub struct BpfArray {
    value_size: u32,
    percpu: bool,
    /// The memory of the map, for `map_mem_usage`.
    mem: u64,
    value: Vec<Arc<Elem>>,
}

impl BpfArray {
    /// Makes an array with all values zero, as `array_map_alloc` of Linux. Linux rounds the
    /// size up to a power of 2 against speculation, and rukernel uses the same size to find an
    /// overflow and to check the free memory.
    pub fn alloc(attr: &MapAttr, nr_cpus: usize, avail: u64) -> Result<Self> {
        let percpu = attr.map_type == BPF_MAP_TYPE_PERCPU_ARRAY;
        let elem_size = round_up8(attr.value_size) as u64;
        let mask64: u64 = (1u64 << (32 - (attr.max_entries - 1).leading_zeros())) - 1;
        let max_entries = (mask64 as u32).wrapping_add(1);
        if max_entries < attr.max_entries {
            return Err(Errno::E2BIG);
        }
        let nr_vals = if percpu { nr_cpus } else { 1 };
        let mem = 320 + u64::from(attr.max_entries) * (ELEM_OVERHEAD + elem_size * nr_vals as u64);
        if mem > avail {
            return Err(Errno::ENOMEM);
        }
        let mut value = Vec::new();
        value.try_reserve_exact(attr.max_entries as usize).map_err(|_| Errno::ENOMEM)?;
        for _ in 0..attr.max_entries {
            value.push(Arc::new(Elem::zeroed(nr_vals, elem_size as usize)?));
        }
        Ok(Self { value_size: attr.value_size, percpu, mem, value })
    }

    fn index(key: &[u8]) -> usize {
        u32::from_ne_bytes([key[0], key[1], key[2], key[3]]) as usize
    }
}

impl BpfMapOps for BpfArray {
    /// `array_map_lookup_elem` and `percpu_array_map_lookup_elem` of Linux.
    fn map_lookup_elem(&self, key: &[u8]) -> Option<Arc<Elem>> {
        self.value.get(Self::index(key)).cloned()
    }

    /// `array_map_update_elem` of Linux for a program, and `bpf_percpu_array_update` of Linux
    /// for a system call on a per CPU array.
    fn map_update_elem(
        &self,
        key: &[u8],
        value: &[u8],
        map_flags: u64,
        onallcpus: bool,
        env: MapEnv,
    ) -> Result<()> {
        let index = Self::index(key);
        if self.percpu && onallcpus {
            if map_flags & BPF_F_LOCK != 0 || u64::from(map_flags as u32) > BPF_F_ALL_CPUS {
                // Unknown flags.
                return Err(Errno::EINVAL);
            }
            let elem = self.value.get(index).ok_or(Errno::E2BIG)?;
            if map_flags == BPF_NOEXIST {
                // All elements exist.
                return Err(Errno::EEXIST);
            }
            pcpu_copy_value(elem, self.value_size, value, true, map_flags, env.cpu);
            return Ok(());
        }
        if (map_flags & !BPF_F_LOCK) > BPF_EXIST {
            return Err(Errno::EINVAL);
        }
        let elem = self.value.get(index).ok_or(Errno::E2BIG)?;
        if map_flags & BPF_NOEXIST != 0 {
            return Err(Errno::EEXIST);
        }
        if map_flags & BPF_F_LOCK != 0 {
            // No value has a `bpf_spin_lock`, because there is no BTF.
            return Err(Errno::EINVAL);
        }
        pcpu_copy_value(elem, self.value_size, value, false, map_flags, env.cpu);
        Ok(())
    }

    /// `array_map_delete_elem` of Linux: the elements of an array cannot be removed.
    fn map_delete_elem(&self, _key: &[u8]) -> Result<()> {
        Err(Errno::EINVAL)
    }

    /// `array_map_get_next_key` of Linux.
    fn map_get_next_key(&self, key: Option<&[u8]>, next_key: &mut [u8]) -> Result<()> {
        let index = key.map_or(u32::MAX as usize, Self::index);
        let next: u32 = if index >= self.value.len() {
            0
        } else if index == self.value.len() - 1 {
            return Err(Errno::ENOENT);
        } else {
            index as u32 + 1
        };
        next_key[..4].copy_from_slice(&next.to_ne_bytes());
        Ok(())
    }

    fn map_mem_usage(&self) -> u64 {
        self.mem
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::uapi::elem::{BPF_ANY, BPF_F_CPU};

    const ENV: MapEnv = MapEnv { nr_cpus: 2, cpu: 0 };

    fn attr(map_type: u32) -> MapAttr {
        MapAttr { map_type, key_size: 4, value_size: 4, max_entries: 3, ..MapAttr::default() }
    }

    fn key(i: u32) -> [u8; 4] {
        i.to_ne_bytes()
    }

    #[test]
    fn an_array_has_all_elements() {
        let m = BpfArray::alloc(&attr(BPF_MAP_TYPE_ARRAY), 2, u64::MAX).unwrap();
        let mut b = [9u8; 4];
        m.map_lookup_elem(&key(2)).unwrap().value(0).read(0, &mut b);
        assert_eq!(b, [0; 4]);
        assert!(m.map_lookup_elem(&key(3)).is_none());
        assert_eq!(m.map_update_elem(&key(3), b"abcd", BPF_ANY, false, ENV), Err(Errno::E2BIG));
        assert_eq!(
            m.map_update_elem(&key(1), b"abcd", BPF_NOEXIST, false, ENV),
            Err(Errno::EEXIST)
        );
        m.map_update_elem(&key(1), b"abcd", BPF_EXIST, false, ENV).unwrap();
        m.map_lookup_elem(&key(1)).unwrap().value(0).read(0, &mut b);
        assert_eq!(&b, b"abcd");
        assert_eq!(m.map_delete_elem(&key(1)), Err(Errno::EINVAL));
    }

    #[test]
    fn get_next_key_walks_the_indexes() {
        let m = BpfArray::alloc(&attr(BPF_MAP_TYPE_ARRAY), 2, u64::MAX).unwrap();
        let mut next = [0u8; 4];
        m.map_get_next_key(None, &mut next).unwrap();
        assert_eq!(next, key(0));
        m.map_get_next_key(Some(&key(7)), &mut next).unwrap();
        assert_eq!(next, key(0));
        m.map_get_next_key(Some(&key(1)), &mut next).unwrap();
        assert_eq!(next, key(2));
        assert_eq!(m.map_get_next_key(Some(&key(2)), &mut next), Err(Errno::ENOENT));
    }

    #[test]
    fn a_percpu_array_takes_all_values() {
        let m = BpfArray::alloc(&attr(BPF_MAP_TYPE_PERCPU_ARRAY), 2, u64::MAX).unwrap();
        m.map_update_elem(&key(0), b"1111....2222....", BPF_ANY, true, ENV).unwrap();
        m.map_update_elem(&key(0), b"3333", BPF_F_CPU | (1 << 32), true, ENV).unwrap();
        let e = m.map_lookup_elem(&key(0)).unwrap();
        let mut b = [0u8; 8];
        e.value(0).read(0, &mut b);
        assert_eq!(&b, b"1111\0\0\0\0");
        e.value(1).read(0, &mut b);
        assert_eq!(&b, b"3333\0\0\0\0");
        assert_eq!(m.map_update_elem(&key(0), b"3333", BPF_NOEXIST, true, ENV), Err(Errno::EEXIST));
    }

    #[test]
    fn bad_attributes_are_refused() {
        let mut a = attr(BPF_MAP_TYPE_ARRAY);
        a.key_size = 8;
        assert_eq!(array_map_alloc_check(&a), Err(Errno::EINVAL));
        let mut a = attr(BPF_MAP_TYPE_PERCPU_ARRAY);
        a.map_flags = BPF_F_MMAPABLE;
        assert_eq!(array_map_alloc_check(&a), Err(Errno::EINVAL));
        let mut a = attr(BPF_MAP_TYPE_ARRAY);
        a.max_entries = u32::MAX;
        assert_eq!(BpfArray::alloc(&a, 1, u64::MAX).err(), Some(Errno::E2BIG));
        a.max_entries = 1 << 20;
        assert_eq!(BpfArray::alloc(&a, 1, 1 << 20).err(), Some(Errno::ENOMEM));
    }
}
