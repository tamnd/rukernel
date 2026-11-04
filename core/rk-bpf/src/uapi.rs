//! The numbers of include/uapi/linux/bpf.h of Linux 7.3 that rukernel uses.

/// The commands of `bpf(2)`, `enum bpf_cmd`.
pub mod cmd {
    /// Creates a map.
    pub const BPF_MAP_CREATE: u32 = 0;
    /// Copies the value of a key.
    pub const BPF_MAP_LOOKUP_ELEM: u32 = 1;
    /// Adds or changes an element.
    pub const BPF_MAP_UPDATE_ELEM: u32 = 2;
    /// Removes an element.
    pub const BPF_MAP_DELETE_ELEM: u32 = 3;
    /// Gives the key after a key.
    pub const BPF_MAP_GET_NEXT_KEY: u32 = 4;
    /// Loads a program.
    pub const BPF_PROG_LOAD: u32 = 5;
    /// Pins a map or a program in bpffs.
    pub const BPF_OBJ_PIN: u32 = 6;
    /// Gives a descriptor of a pinned object.
    pub const BPF_OBJ_GET: u32 = 7;
    /// Makes the map read only for system calls.
    pub const BPF_MAP_FREEZE: u32 = 22;
    /// The flag of the command that tells that the call has `struct bpf_common_attr`.
    pub const BPF_COMMON_ATTRS: u32 = 1 << 16;
}

/// The map types, `enum bpf_map_type`.
pub mod map_type {
    /// A hash table.
    pub const BPF_MAP_TYPE_HASH: u32 = 1;
    /// An array with a `u32` index as the key.
    pub const BPF_MAP_TYPE_ARRAY: u32 = 2;
    /// An array of programs for tail calls.
    pub const BPF_MAP_TYPE_PROG_ARRAY: u32 = 3;
    /// A hash table with one value for each CPU.
    pub const BPF_MAP_TYPE_PERCPU_HASH: u32 = 5;
    /// An array with one value for each CPU.
    pub const BPF_MAP_TYPE_PERCPU_ARRAY: u32 = 6;
    /// A hash table that removes the elements that were not used for the longest time.
    pub const BPF_MAP_TYPE_LRU_HASH: u32 = 9;
    /// The per CPU form of `BPF_MAP_TYPE_LRU_HASH`.
    pub const BPF_MAP_TYPE_LRU_PERCPU_HASH: u32 = 10;
    /// A trie that finds the longest prefix that matches a key.
    pub const BPF_MAP_TYPE_LPM_TRIE: u32 = 11;
    /// A ring buffer that programs write and a process reads.
    pub const BPF_MAP_TYPE_RINGBUF: u32 = 27;
    /// The last map type of Linux 7.3, `BPF_MAP_TYPE_RHASH`.
    pub const LAST: u32 = 34;
}

/// The flags of `BPF_MAP_UPDATE_ELEM` and `BPF_MAP_LOOKUP_ELEM`.
pub mod elem {
    /// Adds the element or changes it.
    pub const BPF_ANY: u64 = 0;
    /// Adds the element only if it does not exist.
    pub const BPF_NOEXIST: u64 = 1;
    /// Changes the element only if it exists.
    pub const BPF_EXIST: u64 = 2;
    /// Copies the value with the `bpf_spin_lock` of the value held.
    pub const BPF_F_LOCK: u64 = 4;
    /// The value is for the CPU in the high 32 bits of the flags.
    pub const BPF_F_CPU: u64 = 8;
    /// The one value is for all CPUs.
    pub const BPF_F_ALL_CPUS: u64 = 16;
}

/// The flags of `BPF_MAP_CREATE`.
pub mod flags {
    /// Do not allocate the elements of a hash table at the start.
    pub const BPF_F_NO_PREALLOC: u32 = 1 << 0;
    /// One LRU list for each CPU.
    pub const BPF_F_NO_COMMON_LRU: u32 = 1 << 1;
    /// `numa_node` has the memory node.
    pub const BPF_F_NUMA_NODE: u32 = 1 << 2;
    /// The system calls can only read the map.
    pub const BPF_F_RDONLY: u32 = 1 << 3;
    /// The system calls can only write the map.
    pub const BPF_F_WRONLY: u32 = 1 << 4;
    /// The hash function has the seed 0, for tests.
    pub const BPF_F_ZERO_SEED: u32 = 1 << 6;
    /// The programs can only read the map.
    pub const BPF_F_RDONLY_PROG: u32 = 1 << 7;
    /// The programs can only write the map.
    pub const BPF_F_WRONLY_PROG: u32 = 1 << 8;
    /// The map can be mapped with `mmap`.
    pub const BPF_F_MMAPABLE: u32 = 1 << 10;
    /// Keep the elements of a perf event array.
    pub const BPF_F_PRESERVE_ELEMS: u32 = 1 << 11;
    /// The map can be an inner map with a different `max_entries`.
    pub const BPF_F_INNER_MAP: u32 = 1 << 12;
    /// `path_fd` has the directory of `pathname`, for `BPF_OBJ_PIN` and `BPF_OBJ_GET`.
    pub const BPF_F_PATH_FD: u32 = 1 << 14;
    /// `map_token_fd` has a BPF token.
    pub const BPF_F_TOKEN_FD: u32 = 1 << 16;
    /// The flags of the access, `BPF_F_ACCESS_MASK`.
    pub const BPF_F_ACCESS_MASK: u32 =
        BPF_F_RDONLY | BPF_F_RDONLY_PROG | BPF_F_WRONLY | BPF_F_WRONLY_PROG;
}

/// The length of the name of a map or a program, with its zero byte, `BPF_OBJ_NAME_LEN`.
pub const BPF_OBJ_NAME_LEN: usize = 16;

/// The capability that allows the use of BPF, `CAP_BPF` of include/uapi/linux/capability.h.
pub const CAP_BPF: u32 = 39;
