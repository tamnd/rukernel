//! The hash maps, kernel/bpf/hashtab.c of Linux: `BPF_MAP_TYPE_HASH` and
//! `BPF_MAP_TYPE_PERCPU_HASH`.
//!
//! Linux keeps the elements in buckets of a hash table, and the order of `BPF_MAP_GET_NEXT_KEY`
//! is the order of the buckets, which is not defined. rukernel keeps the elements in a sorted
//! tree, so `BPF_MAP_GET_NEXT_KEY` gives the keys in byte order. A program must not use the
//! order, so both are correct.

use super::{
    BpfMapOps, Elem, MapAttr, MapEnv, Result, bpf_map_flags_access_ok, pcpu_copy_value,
    pcpu_init_value, round_up8,
};
use crate::uapi::elem::{BPF_EXIST, BPF_F_ALL_CPUS, BPF_F_LOCK, BPF_NOEXIST};
use crate::uapi::flags::*;
use crate::uapi::map_type::{BPF_MAP_TYPE_LRU_PERCPU_HASH, BPF_MAP_TYPE_PERCPU_HASH};
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_frame::sync::SpinLock;

/// The flags that a hash map accepts, `HTAB_CREATE_FLAG_MASK` of Linux.
const HTAB_CREATE_FLAG_MASK: u32 =
    BPF_F_NO_PREALLOC | BPF_F_NO_COMMON_LRU | BPF_F_NUMA_NODE | BPF_F_ACCESS_MASK | BPF_F_ZERO_SEED;

/// `KMALLOC_MAX_SIZE` of Linux on x86_64 and arm64 with 4 KiB pages.
pub(crate) const KMALLOC_MAX_SIZE: u64 = 1 << 22;

/// `sizeof(struct htab_elem)` of Linux on a 64-bit machine.
const HTAB_ELEM_SIZE: u64 = 48;

/// The largest per CPU value, `PCPU_MIN_UNIT_SIZE` of Linux.
pub(crate) const PCPU_MIN_UNIT_SIZE: usize = 32 << 10;

/// Checks the attributes of a new hash map, `htab_map_alloc_check` of Linux. The caller checked
/// `BPF_F_ZERO_SEED` against `CAP_SYS_ADMIN`.
pub fn htab_map_alloc_check(attr: &MapAttr) -> Result<()> {
    let percpu = matches!(attr.map_type, BPF_MAP_TYPE_PERCPU_HASH | BPF_MAP_TYPE_LRU_PERCPU_HASH);
    let percpu_lru = attr.map_flags & BPF_F_NO_COMMON_LRU != 0;
    if attr.map_flags & !HTAB_CREATE_FLAG_MASK != 0 || !bpf_map_flags_access_ok(attr.map_flags) {
        return Err(Errno::EINVAL);
    }
    // rukernel has no LRU hash map yet, so `lru` is false here.
    if percpu_lru {
        return Err(Errno::EINVAL);
    }
    if attr.map_flags & BPF_F_NUMA_NODE != 0 && percpu {
        return Err(Errno::EINVAL);
    }
    if attr.max_entries == 0 || attr.key_size == 0 || attr.value_size == 0 {
        return Err(Errno::EINVAL);
    }
    if u64::from(attr.key_size) + u64::from(attr.value_size) >= KMALLOC_MAX_SIZE - HTAB_ELEM_SIZE {
        return Err(Errno::E2BIG);
    }
    if percpu && round_up8(attr.value_size) > PCPU_MIN_UNIT_SIZE {
        return Err(Errno::E2BIG);
    }
    Ok(())
}

/// A hash map, `struct bpf_htab` of Linux.
pub struct BpfHtab {
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    /// The number of values of an element: the number of CPUs, or 1.
    nr_vals: usize,
    percpu: bool,
    table: SpinLock<BTreeMap<Vec<u8>, Arc<Elem>>>,
}

impl BpfHtab {
    /// Makes an empty hash map, as `htab_map_alloc` of Linux. A map with `BPF_F_NO_PREALLOC`
    /// unset takes the memory of all elements in Linux, so rukernel checks that this memory is
    /// free. rukernel makes each element when the map gets it.
    pub fn alloc(attr: &MapAttr, nr_cpus: usize, avail: u64) -> Result<Self> {
        let percpu = attr.map_type == BPF_MAP_TYPE_PERCPU_HASH;
        let nr_vals = if percpu { nr_cpus } else { 1 };
        if attr.map_flags & BPF_F_NO_PREALLOC == 0 {
            let elem = HTAB_ELEM_SIZE
                + u64::from(attr.key_size)
                + (round_up8(attr.value_size) * nr_vals) as u64;
            if elem.saturating_mul(u64::from(attr.max_entries)) > avail {
                return Err(Errno::ENOMEM);
            }
        }
        Ok(Self {
            key_size: attr.key_size,
            value_size: attr.value_size,
            max_entries: attr.max_entries,
            nr_vals,
            percpu,
            table: SpinLock::new(BTreeMap::new()),
        })
    }

    /// The number of elements.
    pub fn len(&self) -> usize {
        self.table.lock().len()
    }

    /// Tells if the map has no elements.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Checks the flags of an update against the old element, `check_flags` of Linux.
fn check_flags(l_old: bool, map_flags: u64) -> Result<()> {
    if l_old && map_flags & !BPF_F_LOCK == BPF_NOEXIST {
        // The element with the key exists.
        return Err(Errno::EEXIST);
    }
    if !l_old && map_flags & !BPF_F_LOCK == BPF_EXIST {
        // The element with the key does not exist.
        return Err(Errno::ENOENT);
    }
    Ok(())
}

/// Checks the flags of an update of a per CPU hash map, `htab_map_check_update_flags` of Linux.
fn htab_map_check_update_flags(onallcpus: bool, map_flags: u64) -> Result<()> {
    if !onallcpus && map_flags > BPF_EXIST {
        return Err(Errno::EINVAL);
    }
    if onallcpus && (map_flags & BPF_F_LOCK != 0 || u64::from(map_flags as u32) > BPF_F_ALL_CPUS) {
        return Err(Errno::EINVAL);
    }
    Ok(())
}

impl BpfMapOps for BpfHtab {
    fn map_lookup_elem(&self, key: &[u8]) -> Option<Arc<Elem>> {
        self.table.lock().get(&key[..self.key_size as usize]).cloned()
    }

    /// `htab_map_update_elem` and `__htab_percpu_map_update_elem` of Linux.
    fn map_update_elem(
        &self,
        key: &[u8],
        value: &[u8],
        map_flags: u64,
        onallcpus: bool,
        env: MapEnv,
    ) -> Result<()> {
        if self.percpu {
            htab_map_check_update_flags(onallcpus, map_flags)?;
        } else if (map_flags & !BPF_F_LOCK) > BPF_EXIST {
            // Unknown flags.
            return Err(Errno::EINVAL);
        }
        if map_flags & BPF_F_LOCK != 0 {
            // No value has a `bpf_spin_lock`, because there is no BTF.
            return Err(Errno::EINVAL);
        }
        let key = &key[..self.key_size as usize];
        let mut table = self.table.lock();
        let l_old = table.get(key).cloned();
        check_flags(l_old.is_some(), map_flags)?;
        if self.percpu
            && let Some(old) = &l_old
        {
            // The per CPU map changes the values in place.
            pcpu_copy_value(old, self.value_size, value, onallcpus, map_flags, env.cpu);
            return Ok(());
        }
        if l_old.is_none() && table.len() >= self.max_entries as usize {
            // All elements are in use, as `alloc_htab_elem` of Linux.
            return Err(Errno::E2BIG);
        }
        let l_new =
            pcpu_init_value(self.nr_vals, self.value_size, value, onallcpus, map_flags, env.cpu)?;
        let mut k = Vec::new();
        k.try_reserve_exact(key.len()).map_err(|_| Errno::ENOMEM)?;
        k.extend_from_slice(key);
        // A program that holds the old element keeps it, as with RCU in Linux.
        table.insert(k, Arc::new(l_new));
        Ok(())
    }

    /// `htab_map_delete_elem` of Linux.
    fn map_delete_elem(&self, key: &[u8]) -> Result<()> {
        let removed = self.table.lock().remove(&key[..self.key_size as usize]);
        removed.map(drop).ok_or(Errno::ENOENT)
    }

    /// `htab_map_get_next_key` of Linux. A key that is not in the map gives the first key.
    fn map_get_next_key(&self, key: Option<&[u8]>, next_key: &mut [u8]) -> Result<()> {
        let table = self.table.lock();
        let found = match key.map(|k| &k[..self.key_size as usize]) {
            Some(k) if table.contains_key(k) => table
                .range::<[u8], _>((core::ops::Bound::Excluded(k), core::ops::Bound::Unbounded))
                .next(),
            _ => table.iter().next(),
        };
        let (k, _) = found.ok_or(Errno::ENOENT)?;
        next_key[..k.len()].copy_from_slice(k);
        Ok(())
    }

    /// `htab_map_mem_usage` of Linux, with the elements that are in the map.
    fn map_mem_usage(&self) -> u64 {
        let elem = HTAB_ELEM_SIZE
            + u64::from(self.key_size)
            + (round_up8(self.value_size) * self.nr_vals) as u64;
        256 + elem * self.len() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::uapi::elem::{BPF_ANY, BPF_F_CPU};
    use crate::uapi::map_type::BPF_MAP_TYPE_HASH;

    const ENV: MapEnv = MapEnv { nr_cpus: 2, cpu: 1 };

    fn attr(map_type: u32, max_entries: u32) -> MapAttr {
        MapAttr { map_type, key_size: 4, value_size: 4, max_entries, ..MapAttr::default() }
    }

    fn val(e: &Elem, cpu: usize) -> [u8; 4] {
        let mut b = [0; 4];
        e.value(cpu).read(0, &mut b);
        b
    }

    #[test]
    fn the_flags_of_an_update_are_checked() {
        let m = BpfHtab::alloc(&attr(BPF_MAP_TYPE_HASH, 2), 2, u64::MAX).unwrap();
        assert_eq!(m.map_update_elem(b"k001", b"v001", BPF_EXIST, false, ENV), Err(Errno::ENOENT));
        m.map_update_elem(b"k001", b"v001", BPF_NOEXIST, false, ENV).unwrap();
        assert_eq!(
            m.map_update_elem(b"k001", b"v002", BPF_NOEXIST, false, ENV),
            Err(Errno::EEXIST)
        );
        m.map_update_elem(b"k001", b"v002", BPF_EXIST, false, ENV).unwrap();
        m.map_update_elem(b"k002", b"v002", BPF_ANY, false, ENV).unwrap();
        assert_eq!(m.map_update_elem(b"k003", b"v003", BPF_ANY, false, ENV), Err(Errno::E2BIG));
        assert_eq!(m.map_update_elem(b"k003", b"v003", 3, false, ENV), Err(Errno::EINVAL));
        assert_eq!(&val(&m.map_lookup_elem(b"k001").unwrap(), 0), b"v002");
    }

    #[test]
    fn get_next_key_walks_all_keys() {
        let m = BpfHtab::alloc(&attr(BPF_MAP_TYPE_HASH, 8), 2, u64::MAX).unwrap();
        for k in [b"k003", b"k001", b"k002"] {
            m.map_update_elem(k, b"vvvv", BPF_ANY, false, ENV).unwrap();
        }
        let mut next = [0u8; 4];
        m.map_get_next_key(Some(b"none"), &mut next).unwrap();
        assert_eq!(&next, b"k001");
        m.map_get_next_key(Some(b"k002"), &mut next).unwrap();
        assert_eq!(&next, b"k003");
        assert_eq!(m.map_get_next_key(Some(b"k003"), &mut next), Err(Errno::ENOENT));
        m.map_delete_elem(b"k002").unwrap();
        assert_eq!(m.map_delete_elem(b"k002"), Err(Errno::ENOENT));
    }

    #[test]
    fn a_percpu_hash_has_a_value_for_each_cpu() {
        let m = BpfHtab::alloc(&attr(BPF_MAP_TYPE_PERCPU_HASH, 2), 2, u64::MAX).unwrap();
        // A program sets the value of its CPU, and the other CPUs get zero.
        m.map_update_elem(b"k001", b"abcd", BPF_ANY, false, ENV).unwrap();
        let e = m.map_lookup_elem(b"k001").unwrap();
        assert_eq!((val(&e, 0), val(&e, 1)), ([0; 4], *b"abcd"));
        // A system call gives one value for each CPU, at 8 byte steps.
        m.map_update_elem(b"k001", b"1111....2222....", BPF_ANY, true, ENV).unwrap();
        assert_eq!((val(&e, 0), val(&e, 1)), (*b"1111", *b"2222"));
        m.map_update_elem(b"k001", b"3333", BPF_ANY | BPF_F_ALL_CPUS, true, ENV).unwrap();
        assert_eq!((val(&e, 0), val(&e, 1)), (*b"3333", *b"3333"));
        m.map_update_elem(b"k001", b"4444", BPF_F_CPU | (1 << 32), true, ENV).unwrap();
        assert_eq!((val(&e, 0), val(&e, 1)), (*b"3333", *b"4444"));
        assert_eq!(m.map_update_elem(b"k001", b"4444", BPF_F_LOCK, true, ENV), Err(Errno::EINVAL));
    }

    #[test]
    fn bad_attributes_are_refused() {
        let mut a = attr(BPF_MAP_TYPE_HASH, 1);
        a.key_size = 0;
        assert_eq!(htab_map_alloc_check(&a), Err(Errno::EINVAL));
        let mut a = attr(BPF_MAP_TYPE_PERCPU_HASH, 1);
        a.value_size = 40000;
        assert_eq!(htab_map_alloc_check(&a), Err(Errno::E2BIG));
        let mut a = attr(BPF_MAP_TYPE_HASH, 1);
        a.map_flags = BPF_F_MMAPABLE;
        assert_eq!(htab_map_alloc_check(&a), Err(Errno::EINVAL));
        assert_eq!(
            BpfHtab::alloc(&attr(BPF_MAP_TYPE_HASH, 1000), 1, 1000).err(),
            Some(Errno::ENOMEM)
        );
    }
}
