//! The longest prefix match trie, kernel/bpf/lpm_trie.c of Linux: `BPF_MAP_TYPE_LPM_TRIE`.
//!
//! The key is `struct bpf_lpm_trie_key_u8`: a `u32` prefix length and the data, such as an IP
//! address. A lookup gives the element with the longest prefix that matches the key. The trie
//! is a binary tree, as in Linux. An intermediate node (`LPM_TREE_NODE_FLAG_IM`) has no value
//! and always has two children. rukernel keeps the nodes in a table and uses indexes in place of
//! pointers, and one lock for the trie, as `trie->lock` of Linux.

use super::hashtab::KMALLOC_MAX_SIZE;
use super::{BpfMapOps, Elem, MapAttr, MapEnv, Result, bpf_map_flags_access_ok, round_up8};
use crate::uapi::elem::{BPF_EXIST, BPF_NOEXIST};
use crate::uapi::flags::{BPF_F_ACCESS_MASK, BPF_F_NO_PREALLOC, BPF_F_NUMA_NODE};
use alloc::sync::Arc;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_frame::sync::SpinLock;

/// The flags that a trie accepts, `LPM_CREATE_FLAG_MASK` of Linux.
const LPM_CREATE_FLAG_MASK: u32 = BPF_F_NO_PREALLOC | BPF_F_NUMA_NODE | BPF_F_ACCESS_MASK;
/// The largest data of a key, `LPM_DATA_SIZE_MAX` of Linux.
const LPM_DATA_SIZE_MAX: u32 = 256;
/// The smallest data of a key, `LPM_DATA_SIZE_MIN` of Linux.
const LPM_DATA_SIZE_MIN: u32 = 1;
/// The size of the prefix length before the data, `offsetof(struct bpf_lpm_trie_key_u8, data)`.
const LPM_KEY_HDR: u32 = 4;
/// `sizeof(struct lpm_trie_node)` of Linux on a 64-bit machine.
const LPM_NODE_SIZE: u64 = 32;
/// The largest value, `LPM_VAL_SIZE_MAX` of Linux.
const LPM_VAL_SIZE_MAX: u64 = KMALLOC_MAX_SIZE - LPM_DATA_SIZE_MAX as u64 - LPM_NODE_SIZE;

/// A node of the trie, `struct lpm_trie_node` of Linux.
struct LpmTrieNode {
    child: [Option<usize>; 2],
    prefixlen: u32,
    /// `None` for an intermediate node, `LPM_TREE_NODE_FLAG_IM` of Linux.
    value: Option<Arc<Elem>>,
    data: Vec<u8>,
}

impl LpmTrieNode {
    fn is_im(&self) -> bool {
        self.value.is_none()
    }
}

/// The place of a node: the root, or a child of a node.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Slot {
    Root,
    Child(usize, usize),
}

/// The nodes of a trie.
struct Nodes {
    root: Option<usize>,
    /// A freed node stays in the table with no value and no data, and its index is in `free`.
    nodes: Vec<LpmTrieNode>,
    free: Vec<usize>,
    n_entries: u32,
}

impl Nodes {
    fn node(&self, i: usize) -> &LpmTrieNode {
        &self.nodes[i]
    }

    fn node_mut(&mut self, i: usize) -> &mut LpmTrieNode {
        &mut self.nodes[i]
    }

    fn get(&self, slot: Slot) -> Option<usize> {
        match slot {
            Slot::Root => self.root,
            Slot::Child(n, bit) => self.node(n).child[bit],
        }
    }

    fn set(&mut self, slot: Slot, to: Option<usize>) {
        match slot {
            Slot::Root => self.root = to,
            Slot::Child(n, bit) => self.node_mut(n).child[bit] = to,
        }
    }

    /// Puts a node in the table, as `lpm_trie_node_alloc` of Linux.
    fn alloc(&mut self, node: LpmTrieNode) -> Result<usize> {
        if let Some(i) = self.free.pop() {
            self.nodes[i] = node;
            return Ok(i);
        }
        self.nodes.try_reserve(1).map_err(|_| Errno::ENOMEM)?;
        self.free.try_reserve(self.nodes.len() + 1).map_err(|_| Errno::ENOMEM)?;
        self.nodes.push(node);
        Ok(self.nodes.len() - 1)
    }

    fn release(&mut self, i: usize) {
        let n = &mut self.nodes[i];
        n.child = [None, None];
        n.value = None;
        n.data = Vec::new();
        // `alloc` reserved the room for all indexes.
        self.free.push(i);
    }
}

/// A trie, `struct lpm_trie` of Linux.
pub struct LpmTrie {
    data_size: usize,
    max_prefixlen: u32,
    max_entries: u32,
    value_size: u32,
    lock: SpinLock<Nodes>,
}

/// The bit `index` of `data`, from the most significant bit of the first byte, `extract_bit` of
/// Linux.
fn extract_bit(data: &[u8], index: usize) -> usize {
    usize::from(data[index / 8] & (1 << (7 - (index % 8))) != 0)
}

/// A key: the prefix length and the data.
fn split_key(key: &[u8], data_size: usize) -> (u32, &[u8]) {
    let prefixlen = u32::from_ne_bytes([key[0], key[1], key[2], key[3]]);
    (prefixlen, &key[4..4 + data_size])
}

/// The count of the first bits that `node` and the key have the same, up to the smaller prefix
/// length, `__longest_prefix_match` of Linux.
fn longest_prefix_match(node: &LpmTrieNode, prefixlen: u32, data: &[u8]) -> u32 {
    let limit = node.prefixlen.min(prefixlen);
    let mut matched = 0u32;
    for (a, b) in node.data.iter().zip(data) {
        let diff = a ^ b;
        matched += diff.leading_zeros();
        if matched >= limit {
            return limit;
        }
        if diff != 0 {
            return matched;
        }
    }
    matched
}

impl LpmTrie {
    /// Checks the attributes and makes an empty trie, `trie_alloc` of Linux. `avail` is the free
    /// memory. A trie does not take memory before it has elements.
    pub fn alloc(attr: &MapAttr, avail: u64) -> Result<Self> {
        if attr.max_entries == 0
            || attr.map_flags & BPF_F_NO_PREALLOC == 0
            || attr.map_flags & !LPM_CREATE_FLAG_MASK != 0
            || !bpf_map_flags_access_ok(attr.map_flags)
            || attr.key_size < LPM_KEY_HDR + LPM_DATA_SIZE_MIN
            || attr.key_size > LPM_KEY_HDR + LPM_DATA_SIZE_MAX
            || attr.value_size < 1
            || u64::from(attr.value_size) > LPM_VAL_SIZE_MAX
        {
            return Err(Errno::EINVAL);
        }
        if avail < 4096 {
            return Err(Errno::ENOMEM);
        }
        let data_size = (attr.key_size - LPM_KEY_HDR) as usize;
        Ok(Self {
            data_size,
            max_prefixlen: data_size as u32 * 8,
            max_entries: attr.max_entries,
            value_size: attr.value_size,
            lock: SpinLock::new(Nodes {
                root: None,
                nodes: Vec::new(),
                free: Vec::new(),
                n_entries: 0,
            }),
        })
    }

    /// Counts a new element, `trie_check_add_elem` of Linux.
    fn trie_check_add_elem(&self, t: &mut Nodes, flags: u64) -> Result<()> {
        if flags == BPF_EXIST {
            return Err(Errno::ENOENT);
        }
        if t.n_entries == self.max_entries {
            return Err(Errno::ENOSPC);
        }
        t.n_entries += 1;
        Ok(())
    }
}

impl BpfMapOps for LpmTrie {
    /// `trie_lookup_elem` of Linux.
    fn map_lookup_elem(&self, key: &[u8]) -> Option<Arc<Elem>> {
        let (prefixlen, data) = split_key(key, self.data_size);
        if prefixlen > self.max_prefixlen {
            return None;
        }
        let t = self.lock.lock();
        let mut found = None;
        let mut cur = t.root;
        while let Some(i) = cur {
            let node = t.node(i);
            // The longest prefix of the node that matches the key. The largest prefix is an
            // exact match.
            let matchlen = longest_prefix_match(node, prefixlen, data);
            if matchlen == self.max_prefixlen {
                found = Some(i);
                break;
            }
            // The node has more bits than the key matches: the parent is the result.
            if matchlen < node.prefixlen {
                break;
            }
            if !node.is_im() {
                found = Some(i);
            }
            let next_bit = extract_bit(data, node.prefixlen as usize);
            cur = node.child[next_bit];
        }
        found.and_then(|i| t.node(i).value.clone())
    }

    /// `trie_update_elem` of Linux.
    fn map_update_elem(
        &self,
        key: &[u8],
        value: &[u8],
        flags: u64,
        _onallcpus: bool,
        _env: MapEnv,
    ) -> Result<()> {
        if flags > BPF_EXIST {
            return Err(Errno::EINVAL);
        }
        let (prefixlen, data) = split_key(key, self.data_size);
        if prefixlen > self.max_prefixlen {
            return Err(Errno::EINVAL);
        }
        // Make and fill a new node.
        let elem = Elem::zeroed(1, round_up8(self.value_size))?;
        elem.value(0).write(0, &value[..self.value_size as usize]);
        let mut node_data = Vec::new();
        node_data.try_reserve_exact(self.data_size).map_err(|_| Errno::ENOMEM)?;
        node_data.extend_from_slice(data);
        let new_node = LpmTrieNode {
            child: [None; 2],
            prefixlen,
            value: Some(Arc::new(elem)),
            data: node_data,
        };

        let mut t = self.lock.lock();
        // Find a slot for the new node: an empty slot, or a slot that an intermediate node must
        // take.
        let mut slot = Slot::Root;
        let mut matchlen = 0;
        let mut node = t.get(slot);
        while let Some(i) = node {
            let n = t.node(i);
            matchlen = longest_prefix_match(n, prefixlen, data);
            if n.prefixlen != matchlen || n.prefixlen == prefixlen {
                break;
            }
            slot = Slot::Child(i, extract_bit(data, n.prefixlen as usize));
            node = t.get(slot);
        }
        let Some(node) = node else {
            // The slot is empty.
            self.trie_check_add_elem(&mut t, flags)?;
            let i = t.alloc(new_node)?;
            t.set(slot, Some(i));
            return Ok(());
        };
        // The slot has the node of the same prefix: the new node takes its place.
        if t.node(node).prefixlen == matchlen {
            if !t.node(node).is_im() {
                if flags == BPF_NOEXIST {
                    return Err(Errno::EEXIST);
                }
            } else {
                self.trie_check_add_elem(&mut t, flags)?;
            }
            let old = t.node_mut(node);
            old.value = new_node.value;
            old.data = new_node.data;
            return Ok(());
        }
        self.trie_check_add_elem(&mut t, flags)?;
        // The new node matches the prefix of the node completely: put it between the node and
        // the slot.
        if matchlen == prefixlen {
            let next_bit = extract_bit(&t.node(node).data, matchlen as usize);
            let i = match t.alloc(new_node) {
                Ok(i) => i,
                Err(e) => {
                    t.n_entries -= 1;
                    return Err(e);
                }
            };
            t.node_mut(i).child[next_bit] = Some(node);
            t.set(slot, Some(i));
            return Ok(());
        }
        // Else add an intermediate node with the two nodes as children.
        let mut im_data = Vec::new();
        if im_data.try_reserve_exact(self.data_size).is_err() {
            t.n_entries -= 1;
            return Err(Errno::ENOMEM);
        }
        im_data.extend_from_slice(&t.node(node).data);
        let new_i = t.alloc(new_node);
        let im_i = t.alloc(LpmTrieNode {
            child: [None; 2],
            prefixlen: matchlen,
            value: None,
            data: im_data,
        });
        let (new_i, im_i) = match (new_i, im_i) {
            (Ok(a), Ok(b)) => (a, b),
            (a, b) => {
                for i in [a, b].into_iter().flatten() {
                    t.release(i);
                }
                t.n_entries -= 1;
                return Err(Errno::ENOMEM);
            }
        };
        t.node_mut(im_i).child = if extract_bit(data, matchlen as usize) == 1 {
            [Some(node), Some(new_i)]
        } else {
            [Some(new_i), Some(node)]
        };
        t.set(slot, Some(im_i));
        Ok(())
    }

    /// `trie_delete_elem` of Linux.
    fn map_delete_elem(&self, key: &[u8]) -> Result<()> {
        let (prefixlen, data) = split_key(key, self.data_size);
        if prefixlen > self.max_prefixlen {
            return Err(Errno::EINVAL);
        }
        let mut t = self.lock.lock();
        // Find the node of the key, its slot, its parent and the slot of the parent.
        let mut trim = Slot::Root;
        let mut trim2 = trim;
        let mut parent = None;
        let mut matchlen = 0;
        let mut node = t.get(trim);
        while let Some(i) = node {
            let n = t.node(i);
            matchlen = longest_prefix_match(n, prefixlen, data);
            if n.prefixlen != matchlen || n.prefixlen == prefixlen {
                break;
            }
            parent = Some(i);
            trim2 = trim;
            trim = Slot::Child(i, extract_bit(data, n.prefixlen as usize));
            node = t.get(trim);
        }
        let node = match node {
            Some(i)
                if t.node(i).prefixlen == prefixlen
                    && t.node(i).prefixlen == matchlen
                    && !t.node(i).is_im() =>
            {
                i
            }
            _ => return Err(Errno::ENOENT),
        };
        t.n_entries -= 1;
        let child = t.node(node).child;
        // A node with two children becomes an intermediate node.
        if child[0].is_some() && child[1].is_some() {
            t.node_mut(node).value = None;
            return Ok(());
        }
        // An intermediate parent of a node without children goes too, and the other child of
        // the parent takes its place. Each intermediate node then has two children.
        if let Some(p) = parent
            && t.node(p).is_im()
            && child == [None, None]
        {
            let pc = t.node(p).child;
            let other = if pc[0] == Some(node) { pc[1] } else { pc[0] };
            t.set(trim2, other);
            t.release(p);
            t.release(node);
            return Ok(());
        }
        // The node has one child or none: the child takes the place of the node.
        t.set(trim, child[0].or(child[1]));
        t.release(node);
        Ok(())
    }

    /// `trie_get_next_key` of Linux. The keys come in postorder, so a more specific key comes
    /// before a less specific key.
    fn map_get_next_key(&self, key: Option<&[u8]>, next_key: &mut [u8]) -> Result<()> {
        let t = self.lock.lock();
        let mut search_root = t.root.ok_or(Errno::ENOENT)?;
        let mut next_node = None;
        let key =
            key.map(|k| split_key(k, self.data_size)).filter(|(p, _)| *p <= self.max_prefixlen);
        if let Some((prefixlen, data)) = key {
            // Find the node of the key.
            let mut node_stack = Vec::new();
            node_stack.try_reserve(self.max_prefixlen as usize + 1).map_err(|_| Errno::ENOMEM)?;
            let mut matchlen = 0;
            let mut cur = Some(search_root);
            while let Some(i) = cur {
                node_stack.push(i);
                let n = t.node(i);
                matchlen = longest_prefix_match(n, prefixlen, data);
                if n.prefixlen != matchlen || n.prefixlen == prefixlen {
                    break;
                }
                cur = n.child[extract_bit(data, n.prefixlen as usize)];
            }
            if let Some(i) = cur
                && t.node(i).prefixlen == matchlen
                && !t.node(i).is_im()
            {
                // Find the first node in postorder after the node of the key.
                let mut node = i;
                let mut found_root = false;
                while node_stack.len() > 1 {
                    let parent = node_stack[node_stack.len() - 2];
                    let p = t.node(parent);
                    if p.child[0] == Some(node)
                        && let Some(right) = p.child[1]
                    {
                        search_root = right;
                        found_root = true;
                        break;
                    }
                    if !p.is_im() {
                        next_node = Some(parent);
                        break;
                    }
                    node = parent;
                    node_stack.pop();
                }
                if next_node.is_none() && !found_root {
                    return Err(Errno::ENOENT);
                }
            }
        }
        if next_node.is_none() {
            // Find the leftmost node that is not intermediate. Each intermediate node has two
            // children, so there is one.
            let mut cur = Some(search_root);
            while let Some(i) = cur {
                let n = t.node(i);
                if n.is_im() {
                    cur = n.child[0];
                } else {
                    next_node = Some(i);
                    cur = n.child[0].or(n.child[1]);
                }
            }
        }
        let n = t.node(next_node.ok_or(Errno::ENOENT)?);
        next_key[..4].copy_from_slice(&n.prefixlen.to_ne_bytes());
        next_key[4..4 + self.data_size].copy_from_slice(&n.data);
        Ok(())
    }

    /// `trie_mem_usage` of Linux.
    fn map_mem_usage(&self) -> u64 {
        let elem_size = LPM_NODE_SIZE + self.data_size as u64 + u64::from(self.value_size);
        let nodes = self.lock.lock().nodes.len() as u64;
        128 + elem_size * nodes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::uapi::elem::BPF_ANY;
    use crate::uapi::map_type::BPF_MAP_TYPE_LPM_TRIE;
    use alloc::vec;

    const ENV: MapEnv = MapEnv { nr_cpus: 1, cpu: 0 };

    fn trie(max_entries: u32) -> LpmTrie {
        let attr = MapAttr {
            map_type: BPF_MAP_TYPE_LPM_TRIE,
            key_size: 8,
            value_size: 1,
            max_entries,
            map_flags: BPF_F_NO_PREALLOC,
            numa_node: 0,
        };
        LpmTrie::alloc(&attr, u64::MAX).unwrap()
    }

    fn key(prefixlen: u32, ip: [u8; 4]) -> Vec<u8> {
        let mut k = prefixlen.to_ne_bytes().to_vec();
        k.extend_from_slice(&ip);
        k
    }

    fn lookup(t: &LpmTrie, ip: [u8; 4]) -> Option<u8> {
        let e = t.map_lookup_elem(&key(32, ip))?;
        let mut b = [0u8];
        e.value(0).read(0, &mut b);
        Some(b[0])
    }

    #[test]
    fn the_longest_prefix_wins() {
        let t = trie(16);
        t.map_update_elem(&key(16, [192, 168, 0, 0]), &[1], BPF_ANY, false, ENV).unwrap();
        t.map_update_elem(&key(24, [192, 168, 0, 0]), &[2], BPF_ANY, false, ENV).unwrap();
        t.map_update_elem(&key(24, [192, 168, 1, 0]), &[3], BPF_ANY, false, ENV).unwrap();
        t.map_update_elem(&key(24, [192, 168, 128, 0]), &[4], BPF_ANY, false, ENV).unwrap();
        assert_eq!(lookup(&t, [192, 168, 0, 9]), Some(2));
        assert_eq!(lookup(&t, [192, 168, 1, 9]), Some(3));
        assert_eq!(lookup(&t, [192, 168, 128, 9]), Some(4));
        assert_eq!(lookup(&t, [192, 168, 2, 9]), Some(1));
        assert_eq!(lookup(&t, [10, 0, 0, 1]), None);

        // The keys come in postorder, as in the example of lpm_trie.c of Linux.
        let mut next = [0u8; 8];
        let mut order = vec![];
        let mut cur: Option<Vec<u8>> = None;
        while t.map_get_next_key(cur.as_deref(), &mut next).is_ok() {
            order.push(next);
            cur = Some(next.to_vec());
        }
        let want: Vec<Vec<u8>> = vec![
            key(24, [192, 168, 0, 0]),
            key(24, [192, 168, 1, 0]),
            key(24, [192, 168, 128, 0]),
            key(16, [192, 168, 0, 0]),
        ];
        assert_eq!(order.iter().map(|k| k.to_vec()).collect::<Vec<_>>(), want);

        t.map_delete_elem(&key(24, [192, 168, 0, 0])).unwrap();
        assert_eq!(lookup(&t, [192, 168, 0, 9]), Some(1));
        assert_eq!(t.map_delete_elem(&key(24, [192, 168, 0, 0])), Err(Errno::ENOENT));
        t.map_delete_elem(&key(16, [192, 168, 0, 0])).unwrap();
        assert_eq!(lookup(&t, [192, 168, 2, 9]), None);
        assert_eq!(lookup(&t, [192, 168, 1, 9]), Some(3));
    }

    #[test]
    fn the_flags_and_the_size_are_checked() {
        let t = trie(1);
        assert_eq!(
            t.map_update_elem(&key(8, [10, 0, 0, 0]), &[1], BPF_EXIST, false, ENV),
            Err(Errno::ENOENT)
        );
        t.map_update_elem(&key(8, [10, 0, 0, 0]), &[1], BPF_NOEXIST, false, ENV).unwrap();
        assert_eq!(
            t.map_update_elem(&key(8, [10, 0, 0, 0]), &[1], BPF_NOEXIST, false, ENV),
            Err(Errno::EEXIST)
        );
        t.map_update_elem(&key(8, [10, 0, 0, 0]), &[5], BPF_EXIST, false, ENV).unwrap();
        assert_eq!(lookup(&t, [10, 1, 2, 3]), Some(5));
        assert_eq!(
            t.map_update_elem(&key(9, [10, 0, 0, 0]), &[1], BPF_ANY, false, ENV),
            Err(Errno::ENOSPC)
        );
        assert_eq!(
            t.map_update_elem(&key(33, [10, 0, 0, 0]), &[1], BPF_ANY, false, ENV),
            Err(Errno::EINVAL)
        );
        assert_eq!(
            t.map_update_elem(&key(8, [10, 0, 0, 0]), &[1], 3, false, ENV),
            Err(Errno::EINVAL)
        );
        let attr = MapAttr {
            map_type: BPF_MAP_TYPE_LPM_TRIE,
            key_size: 8,
            value_size: 1,
            max_entries: 1,
            ..MapAttr::default()
        };
        assert_eq!(LpmTrie::alloc(&attr, u64::MAX).err(), Some(Errno::EINVAL));
    }
}
