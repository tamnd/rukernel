//! The program array, `BPF_MAP_TYPE_PROG_ARRAY` in kernel/bpf/arraymap.c of Linux.
//!
//! The key is a `u32` index and the value is a program. A system call writes the descriptor of
//! a program and reads the ID of the program. A program can use the array only with the helper
//! `bpf_tail_call`, which runs the program at the index in place of the caller.
//!
//! The array holds its programs, and a program holds the arrays that it uses. So that this
//! cycle does not keep the objects for ever, the array removes all its programs when the last
//! descriptor or pin of the array closes, as `prog_array_map_clear` of Linux.

use super::{BpfMapOps, Elem, MapAttr, MapEnv, Result, arraymap::array_map_alloc_check};
use crate::prog::BpfProg;
use crate::uapi::elem::BPF_ANY;
use crate::uapi::flags::{BPF_F_RDONLY_PROG, BPF_F_WRONLY_PROG};
use alloc::sync::Arc;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_frame::sync::SpinLock;

/// The memory of `struct bpf_array` in rukernel, without the slots.
const ARRAY_SIZE: u64 = 320;

/// Checks the attributes of a new program array, `fd_array_map_alloc_check` of Linux. Only
/// descriptors can be in the array.
pub fn fd_array_map_alloc_check(attr: &MapAttr) -> Result<()> {
    if attr.value_size != 4 {
        return Err(Errno::EINVAL);
    }
    if attr.map_flags & (BPF_F_RDONLY_PROG | BPF_F_WRONLY_PROG) != 0 {
        return Err(Errno::EINVAL);
    }
    array_map_alloc_check(attr)
}

/// A program array, `struct bpf_array` with its `ptrs` of Linux.
pub struct ProgArray {
    progs: SpinLock<Vec<Option<Arc<BpfProg>>>>,
    /// The program type of all programs of the array, `map->owner` of Linux. The first program
    /// that uses the array sets it.
    owner: SpinLock<Option<u32>>,
    mem: u64,
}

fn index(key: &[u8]) -> usize {
    u32::from_ne_bytes([key[0], key[1], key[2], key[3]]) as usize
}

impl ProgArray {
    /// Makes an empty array, as `prog_array_map_alloc` of Linux.
    pub fn alloc(attr: &MapAttr, avail: u64) -> Result<Self> {
        let mem = ARRAY_SIZE + u64::from(attr.max_entries) * 8;
        if mem > avail {
            return Err(Errno::ENOMEM);
        }
        let mut progs = Vec::new();
        progs.try_reserve_exact(attr.max_entries as usize).map_err(|_| Errno::ENOMEM)?;
        progs.resize(attr.max_entries as usize, None);
        Ok(Self { progs: SpinLock::new(progs), owner: SpinLock::new(None), mem })
    }

    /// Tells if a program of the type `prog_type` can be in the array or use it, as
    /// `__bpf_prog_map_compatible` of Linux. The first program sets the type of the array.
    /// rukernel has no JIT, no XDP and no cgroup storage, so only the type must be the same.
    pub fn compatible(&self, prog_type: u32) -> bool {
        *self.owner.lock().get_or_insert(prog_type) == prog_type
    }

    /// The program type of the array, after the first program.
    pub fn owner(&self) -> Option<u32> {
        *self.owner.lock()
    }

    /// The program at `index`, for `bpf_tail_call`.
    pub fn get(&self, index: u32) -> Option<Arc<BpfProg>> {
        self.progs.lock().get(index as usize).cloned().flatten()
    }

    /// Puts the program of a descriptor at the index `key`, as `bpf_fd_array_map_update_elem`
    /// of Linux. `prog_get` gives the program of the descriptor.
    pub fn fd_update(
        &self,
        key: &[u8],
        value: &[u8],
        flags: u64,
        prog_get: &dyn Fn(u32) -> Result<Arc<BpfProg>>,
    ) -> Result<()> {
        if flags != BPF_ANY {
            return Err(Errno::EINVAL);
        }
        let i = index(key);
        if i >= self.progs.lock().len() {
            return Err(Errno::E2BIG);
        }
        let ufd = u32::from_ne_bytes([value[0], value[1], value[2], value[3]]);
        // `prog_fd_array_get_ptr` of Linux.
        let prog = prog_get(ufd)?;
        if !self.compatible(prog.prog_type) {
            return Err(Errno::EINVAL);
        }
        // The old program is dropped after the lock.
        let _old = self.progs.lock()[i].replace(prog);
        Ok(())
    }

    /// The ID of the program at the index `key`, as `bpf_fd_array_map_lookup_elem` of Linux.
    pub fn fd_lookup(&self, key: &[u8]) -> Result<u32> {
        self.progs
            .lock()
            .get(index(key))
            .and_then(|p| p.as_ref().map(|p| p.id))
            .ok_or(Errno::ENOENT)
    }

    /// Removes all programs, `bpf_fd_array_map_clear` of Linux.
    fn clear(&self) {
        let old: Vec<_> = self.progs.lock().iter_mut().map(Option::take).collect();
        drop(old);
    }
}

impl BpfMapOps for ProgArray {
    /// `fd_array_map_lookup_elem` of Linux: a program cannot read the array, and the verifier
    /// refuses the call.
    fn map_lookup_elem(&self, _key: &[u8]) -> Option<Arc<Elem>> {
        None
    }

    /// The system calls use [`ProgArray::fd_update`], and the verifier refuses the call of a
    /// program.
    fn map_update_elem(&self, _: &[u8], _: &[u8], _: u64, _: bool, _: MapEnv) -> Result<()> {
        Err(Errno::EINVAL)
    }

    /// `fd_array_map_delete_elem` of Linux.
    fn map_delete_elem(&self, key: &[u8]) -> Result<()> {
        let old = {
            let mut progs = self.progs.lock();
            progs.get_mut(index(key)).ok_or(Errno::E2BIG)?.take()
        };
        old.map(drop).ok_or(Errno::ENOENT)
    }

    /// `array_map_get_next_key` of Linux.
    fn map_get_next_key(&self, key: Option<&[u8]>, next_key: &mut [u8]) -> Result<()> {
        let len = self.progs.lock().len();
        let i = key.map_or(u32::MAX as usize, index);
        let next: u32 = if i >= len {
            0
        } else if i == len - 1 {
            return Err(Errno::ENOENT);
        } else {
            i as u32 + 1
        };
        next_key[..4].copy_from_slice(&next.to_ne_bytes());
        Ok(())
    }

    fn map_mem_usage(&self) -> u64 {
        self.mem
    }

    /// `prog_array_map_clear` of Linux.
    fn map_release_uref(&self) {
        self.clear();
    }

    fn as_prog_array(&self) -> Option<&ProgArray> {
        Some(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::uapi::elem::BPF_NOEXIST;
    use crate::uapi::map_type::BPF_MAP_TYPE_PROG_ARRAY;

    fn attr(value_size: u32, map_flags: u32) -> MapAttr {
        MapAttr {
            map_type: BPF_MAP_TYPE_PROG_ARRAY,
            key_size: 4,
            value_size,
            max_entries: 2,
            map_flags,
            numa_node: 0,
        }
    }

    fn prog(prog_type: u32, id: u32) -> Arc<BpfProg> {
        Arc::new(BpfProg {
            prog_type,
            expected_attach_type: 0,
            insns: Vec::new(),
            used_maps: Vec::new(),
            id,
            name: [0; 16],
            tag: [0; 8],
            gpl_compatible: true,
            verified_insns: 0,
            run_cnt: core::sync::atomic::AtomicU64::new(0),
            load_time: 0,
            uid: 0,
            enforce_expected_attach_type: false,
        })
    }

    fn key(i: u32) -> [u8; 4] {
        i.to_ne_bytes()
    }

    #[test]
    fn the_attributes_of_a_program_array() {
        assert_eq!(fd_array_map_alloc_check(&attr(4, 0)), Ok(()));
        assert_eq!(fd_array_map_alloc_check(&attr(8, 0)), Err(Errno::EINVAL));
        assert_eq!(fd_array_map_alloc_check(&attr(4, BPF_F_RDONLY_PROG)), Err(Errno::EINVAL));
        assert_eq!(fd_array_map_alloc_check(&attr(4, BPF_F_WRONLY_PROG)), Err(Errno::EINVAL));
        assert_eq!(ProgArray::alloc(&attr(4, 0), 100).err(), Some(Errno::ENOMEM));
    }

    #[test]
    fn updates_lookups_and_deletes() {
        let a = ProgArray::alloc(&attr(4, 0), u64::MAX).unwrap();
        let p = prog(1, 9);
        let get = |fd: u32| if fd == 3 { Ok(p.clone()) } else { Err(Errno::EBADF) };
        assert_eq!(
            a.fd_update(&key(0), &3u32.to_ne_bytes(), BPF_NOEXIST, &get),
            Err(Errno::EINVAL)
        );
        assert_eq!(a.fd_update(&key(2), &3u32.to_ne_bytes(), 0, &get), Err(Errno::E2BIG));
        assert_eq!(a.fd_update(&key(0), &4u32.to_ne_bytes(), 0, &get), Err(Errno::EBADF));
        assert_eq!(a.fd_lookup(&key(0)), Err(Errno::ENOENT));
        assert_eq!(a.fd_update(&key(0), &3u32.to_ne_bytes(), 0, &get), Ok(()));
        assert_eq!(a.fd_lookup(&key(0)), Ok(9));
        assert_eq!(a.owner(), Some(1));
        assert!(Arc::ptr_eq(&a.get(0).unwrap(), &p));
        assert!(a.get(1).is_none() && a.get(2).is_none());
        // A program of another type cannot be in the array.
        let other = prog(2, 10);
        assert_eq!(a.fd_update(&key(1), &[0; 4], 0, &|_| Ok(other.clone())), Err(Errno::EINVAL));
        assert!(a.compatible(1) && !a.compatible(2));
        assert_eq!(a.map_delete_elem(&key(2)), Err(Errno::E2BIG));
        assert_eq!(a.map_delete_elem(&key(1)), Err(Errno::ENOENT));
        assert_eq!(a.map_delete_elem(&key(0)), Ok(()));
        assert_eq!(a.fd_lookup(&key(0)), Err(Errno::ENOENT));
        assert!(a.map_lookup_elem(&key(0)).is_none());
        // The last close of the array removes its programs.
        a.fd_update(&key(1), &3u32.to_ne_bytes(), 0, &get).unwrap();
        assert_eq!(Arc::strong_count(&p), 2);
        a.map_release_uref();
        assert_eq!(Arc::strong_count(&p), 1);
        assert_eq!(a.fd_lookup(&key(1)), Err(Errno::ENOENT));
    }

    #[test]
    fn the_next_key() {
        let a = ProgArray::alloc(&attr(4, 0), u64::MAX).unwrap();
        let mut next = [0u8; 4];
        assert_eq!(a.map_get_next_key(None, &mut next), Ok(()));
        assert_eq!(next, key(0));
        assert_eq!(a.map_get_next_key(Some(&key(0)), &mut next), Ok(()));
        assert_eq!(next, key(1));
        assert_eq!(a.map_get_next_key(Some(&key(1)), &mut next), Err(Errno::ENOENT));
        assert_eq!(a.map_get_next_key(Some(&key(7)), &mut next), Ok(()));
        assert_eq!(next, key(0));
    }
}
