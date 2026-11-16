//! The cgroup BPF programs of systemd 257 (Debian 257.13-1~deb13u1), for the pruning of
//! `do_check`. The instructions are the sections of the objects that libsystemd-core-257.so
//! has, and the tests put the maps in the place of the relocations, as libbpf does.
//!
//! `sd_bind4` and `sd_bind6` (socket-bind.bpf.c) have two loops of 128 rounds over the rules
//! of the maps `sd_bind_allow` and `sd_bind_deny`. Without pruning, the verifier stops them at
//! the limit of 1,000,000 instructions. Linux 6.8 (Ubuntu 6.8.0-147) processes 25,505
//! instructions of `sd_bind4` and of `sd_bind6`, and 16 of each `sd_restrictif` program
//! (restrict-ifaces.bpf.c), as `bpftool -d prog loadall` shows. rk-bpf may not need more than
//! two times these numbers.

use super::*;
use crate::map::{MapAttr, map_alloc};
use crate::uapi::flags::{BPF_F_MMAPABLE, BPF_F_RDONLY_PROG};
use crate::uapi::map_type::BPF_MAP_TYPE_HASH;

/// The instructions that Linux 6.8 processes for the programs.
const LINUX_BIND4: u32 = 25_505;
const LINUX_BIND6: u32 = 25_505;
const LINUX_IFACES: u32 = 16;

const SD_BIND4: [u64; 82] = [
    0x00000000000017bf,
    0x00000001000000b7,
    0x0000000000007161,
    0x00000002004b0155,
    0x00000000001c7161,
    0x0000000200490155,
    0x0000000000187161,
    0x00000000fffc1a63,
    0x00000000000008b7,
    0x00000000fffca961,
    0x00000010000009dc,
    0xffffffff00000618,
    0x0000000000000000,
    0x00000000fff88a63,
    0x000000000000a2bf,
    0xfffffff800000207,
    0x0000000000000118,
    0x0000000000000000,
    0x0000000100000085,
    0x0000000000160015,
    0x0000000000000261,
    0x00000000000e621d,
    0x0000000000247161,
    0x0000000000030215,
    0x0000000000007361,
    0x000000ff00000357,
    0x000000000009325d,
    0x0000000000040261,
    0x0000000000010215,
    0x000000000006125d,
    0x0000000000080169,
    0x00000000002e0115,
    0x00000000000a0269,
    0x000000000002922d,
    0x000000000000120f,
    0x00000000002a922d,
    0x0000000100000807,
    0x00000000000081bf,
    0x0000002000000167,
    0x0000002000000177,
    0x0000008000010115,
    0x00000000ffe30005,
    0x0000000000187161,
    0x00000000fffc1a63,
    0x00000000000008b7,
    0x00000000fffca961,
    0x00000010000009dc,
    0xffffffff00000618,
    0x0000000000000000,
    0x00000000fff88a63,
    0x000000000000a2bf,
    0xfffffff800000207,
    0x0000000000000118,
    0x0000000000000000,
    0x0000000100000085,
    0x0000000000160015,
    0x0000000000000261,
    0x00000000000e621d,
    0x0000000000247161,
    0x0000000000030215,
    0x0000000000007361,
    0x000000ff00000357,
    0x000000000009325d,
    0x0000000000040261,
    0x0000000000010215,
    0x000000000006125d,
    0x0000000000080169,
    0x00000000000c0115,
    0x00000000000a0269,
    0x000000000002922d,
    0x000000000000120f,
    0x000000000008922d,
    0x0000000100000807,
    0x00000000000081bf,
    0x0000002000000167,
    0x0000002000000177,
    0x0000008000010115,
    0x00000000ffe30005,
    0x00000001000000b7,
    0x0000000000000095,
    0x00000000000000b7,
    0x00000000fffd0005,
];

const SD_BIND6: [u64; 82] = [
    0x00000000000017bf,
    0x00000001000000b7,
    0x0000000000007161,
    0x0000000a004b0155,
    0x00000000001c7161,
    0x0000000a00490155,
    0x0000000000187161,
    0x00000000fffc1a63,
    0x00000000000008b7,
    0x00000000fffca961,
    0x00000010000009dc,
    0xffffffff00000618,
    0x0000000000000000,
    0x00000000fff88a63,
    0x000000000000a2bf,
    0xfffffff800000207,
    0x0000000000000118,
    0x0000000000000000,
    0x0000000100000085,
    0x0000000000160015,
    0x0000000000000261,
    0x00000000000e621d,
    0x0000000000247161,
    0x0000000000030215,
    0x0000000000007361,
    0x000000ff00000357,
    0x000000000009325d,
    0x0000000000040261,
    0x0000000000010215,
    0x000000000006125d,
    0x0000000000080169,
    0x00000000002e0115,
    0x00000000000a0269,
    0x000000000002922d,
    0x000000000000120f,
    0x00000000002a922d,
    0x0000000100000807,
    0x00000000000081bf,
    0x0000002000000167,
    0x0000002000000177,
    0x0000008000010115,
    0x00000000ffe30005,
    0x0000000000187161,
    0x00000000fffc1a63,
    0x00000000000008b7,
    0x00000000fffca961,
    0x00000010000009dc,
    0xffffffff00000618,
    0x0000000000000000,
    0x00000000fff88a63,
    0x000000000000a2bf,
    0xfffffff800000207,
    0x0000000000000118,
    0x0000000000000000,
    0x0000000100000085,
    0x0000000000160015,
    0x0000000000000261,
    0x00000000000e621d,
    0x0000000000247161,
    0x0000000000030215,
    0x0000000000007361,
    0x000000ff00000357,
    0x000000000009325d,
    0x0000000000040261,
    0x0000000000010215,
    0x000000000006125d,
    0x0000000000080169,
    0x00000000000c0115,
    0x00000000000a0269,
    0x000000000002922d,
    0x000000000000120f,
    0x000000000008922d,
    0x0000000100000807,
    0x00000000000081bf,
    0x0000002000000167,
    0x0000002000000177,
    0x0000008000010115,
    0x00000000ffe30005,
    0x00000001000000b7,
    0x0000000000000095,
    0x00000000000000b7,
    0x00000000fffd0005,
];

/// `sd_restrictif_e` and `sd_restrictif_i` have the same instructions.
const SD_RESTRICTIF: [u64; 19] = [
    0x0000000000281161,
    0x00000000fffc1a63,
    0x000000000000a2bf,
    0xfffffffc00000207,
    0x0000000000000118,
    0x0000000000000000,
    0x0000000100000085,
    0x0000000000000118,
    0x0000000000000000,
    0x0000000000001171,
    0x0000000000030115,
    0x00000001000001b7,
    0x0000000000030015,
    0x0000000000030005,
    0x00000001000001b7,
    0x0000000000010015,
    0x00000000000001b7,
    0x00000000000010bf,
    0x0000000000000095,
];

fn new_map(
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    flags: u32,
) -> Arc<BpfMap> {
    let attr =
        MapAttr { map_type, key_size, value_size, max_entries, map_flags: flags, numa_node: 0 };
    let ops = map_alloc(&attr, 1, u64::MAX).unwrap();
    Arc::new(BpfMap::new(&attr, [0; 16], 1, ops))
}

/// Gives the instructions with the map of the descriptor `fd` at each instruction of `relocs`.
/// The map of a section of data, as `.rodata`, gives the address of its value.
fn program(words: &[u64], relocs: &[(usize, u8, i32)]) -> Vec<BpfInsn> {
    let mut insns: Vec<BpfInsn> =
        words.iter().map(|w| BpfInsn::from_bytes(&w.to_le_bytes())).collect();
    for &(i, src, fd) in relocs {
        insns[i].src_reg = src;
        insns[i].imm = fd;
    }
    insns
}

/// Loads the program as root with the maps at the descriptors 3 and 4, and gives the count of
/// the processed instructions.
fn load(insns: Vec<BpfInsn>, prog_type: u32, attach: u32, maps: [Arc<BpfMap>; 2]) -> u32 {
    let opts = VerifierOpts {
        prog_type,
        expected_attach_type: attach,
        bpf_capable: true,
        allow_ptr_leaks: true,
        strict_alignment: false,
    };
    let mut log = BpfVerifierLog::new(1);
    let r = bpf_check(
        insns,
        &opts,
        &|fd| maps.get((fd - 3) as usize).cloned().ok_or(Errno::EBADF),
        None,
        &mut log,
    );
    match r {
        Ok(v) => v.insn_processed,
        Err(e) => panic!("{e:?}: {}", log.text),
    }
}

/// The maps of socket-bind.bpf.c: `struct socket_bind_rule` has 12 bytes, and a map has
/// `SOCKET_BIND_MAX_RULES` rules.
fn bind_maps() -> [Arc<BpfMap>; 2] {
    [new_map(BPF_MAP_TYPE_ARRAY, 4, 12, 128, 0), new_map(BPF_MAP_TYPE_ARRAY, 4, 12, 128, 0)]
}

#[test]
fn the_socket_bind_programs_of_systemd_load() {
    let relocs = [(16, BPF_PSEUDO_MAP_FD, 3), (52, BPF_PSEUDO_MAP_FD, 4)];
    let n4 = load(
        program(&SD_BIND4, &relocs),
        BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
        BPF_CGROUP_INET4_BIND,
        bind_maps(),
    );
    let n6 = load(
        program(&SD_BIND6, &relocs),
        BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
        BPF_CGROUP_INET6_BIND,
        bind_maps(),
    );
    assert!(n4 <= 2 * LINUX_BIND4, "sd_bind4: {n4} insns, Linux {LINUX_BIND4}");
    assert!(n6 <= 2 * LINUX_BIND6, "sd_bind6: {n6} insns, Linux {LINUX_BIND6}");
}

#[test]
fn the_restrict_ifaces_programs_of_systemd_load() {
    // `sd_restrictif` is a hash map of the interface indexes, and `.rodata` has
    // `is_allow_list`.
    let relocs = [(4, BPF_PSEUDO_MAP_FD, 3), (7, BPF_PSEUDO_MAP_VALUE, 4)];
    for attach in [BPF_CGROUP_INET_EGRESS, BPF_CGROUP_INET_INGRESS] {
        let maps = [
            new_map(BPF_MAP_TYPE_HASH, 4, 1, 4096, 0),
            new_map(BPF_MAP_TYPE_ARRAY, 4, 1, 1, BPF_F_RDONLY_PROG | BPF_F_MMAPABLE),
        ];
        let n = load(program(&SD_RESTRICTIF, &relocs), BPF_PROG_TYPE_CGROUP_SKB, attach, maps);
        assert!(n <= 2 * LINUX_IFACES, "sd_restrictif: {n} insns, Linux {LINUX_IFACES}");
    }
}
