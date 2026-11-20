//! The cgroup BPF programs of systemd 257 (Debian 257.13-1~deb13u1), for the pruning of
//! `do_check`. The instructions are the sections of the objects that libsystemd-core-257.so
//! has, and the tests put the maps in the place of the relocations, as libbpf does.
//!
//! `sd_bind4` and `sd_bind6` (socket-bind.bpf.c) have two loops of 128 rounds over the rules
//! of the maps `sd_bind_allow` and `sd_bind_deny`. Without pruning, the verifier stops them at
//! the limit of 1,000,000 instructions. Linux 6.8 (Ubuntu 6.8.0-147) processes 25,505
//! instructions of `sd_bind4` and of `sd_bind6`, and 16 of each `sd_restrictif` program
//! (restrict-ifaces.bpf.c), as `bpftool -d prog loadall` shows. rk-bpf may not need more than
//! 1.2 times these numbers.

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
    assert!(n4 * 5 <= LINUX_BIND4 * 6, "sd_bind4: {n4} insns, Linux {LINUX_BIND4}");
    assert!(n6 * 5 <= LINUX_BIND6 * 6, "sd_bind6: {n6} insns, Linux {LINUX_BIND6}");
}

#[test]
fn the_restrict_ifaces_programs_of_systemd_load() {
    // `sd_restrictif` is a hash map of the interface indexes, and `.rodata` has
    // `is_allow_list`. libbpf freezes `.rodata`, so the verifier knows `is_allow_list`.
    let relocs = [(4, BPF_PSEUDO_MAP_FD, 3), (7, BPF_PSEUDO_MAP_VALUE, 4)];
    for attach in [BPF_CGROUP_INET_EGRESS, BPF_CGROUP_INET_INGRESS] {
        let maps = [
            new_map(BPF_MAP_TYPE_HASH, 4, 1, 4096, 0),
            new_map(BPF_MAP_TYPE_ARRAY, 4, 1, 1, BPF_F_RDONLY_PROG | BPF_F_MMAPABLE),
        ];
        maps[1].frozen.store(true, core::sync::atomic::Ordering::Release);
        let n = load(program(&SD_RESTRICTIF, &relocs), BPF_PROG_TYPE_CGROUP_SKB, attach, maps);
        assert!(n * 5 <= LINUX_IFACES * 6, "sd_restrictif: {n} insns, Linux {LINUX_IFACES}");
    }
}

/// Checks a socket filter as root, with an array map of one value of 8 bytes at the
/// descriptor 3.
fn check_filter(insns: &[BpfInsn]) -> ::core::result::Result<u32, (Errno, String)> {
    check_filter_with(insns, new_map(BPF_MAP_TYPE_ARRAY, 4, 8, 1, 0))
}

/// Checks a socket filter as root, with the map `map` at the descriptor 3.
fn check_filter_with(
    insns: &[BpfInsn],
    map: Arc<BpfMap>,
) -> ::core::result::Result<u32, (Errno, String)> {
    let opts = VerifierOpts {
        prog_type: BPF_PROG_TYPE_SOCKET_FILTER,
        expected_attach_type: 0,
        bpf_capable: true,
        allow_ptr_leaks: true,
        strict_alignment: false,
    };
    let mut log = BpfVerifierLog::new(1);
    let r = bpf_check(
        insns.to_vec(),
        &opts,
        &|fd| if fd == 3 { Ok(map.clone()) } else { Err(Errno::EBADF) },
        None,
        &mut log,
    );
    r.map(|v| v.insn_processed).map_err(|e| (e, log.text))
}

#[test]
fn a_frozen_read_only_map_gives_constants() {
    use crate::insn::asm::*;
    // r0 = *(u8 *)(.rodata + 0); if r0 == 0 goto ok; r0 = *(u8 *)(.rodata + 8), out of the
    // value. The verifier knows that the value is 0 only when the map is frozen.
    let mut p = ld_imm64(1, BPF_PSEUDO_MAP_VALUE, 3).to_vec();
    p.extend([
        ldx_mem(BPF_B, 0, 1, 0),
        jmp_imm(BPF_JEQ, 0, 0, 1),
        ldx_mem(BPF_B, 0, 1, 8),
        mov64_imm(0, 0),
        exit(),
    ]);
    let rodata = |max_entries: u32, frozen: bool| {
        let map = new_map(BPF_MAP_TYPE_ARRAY, 4, 1, max_entries, BPF_F_RDONLY_PROG);
        map.frozen.store(frozen, core::sync::atomic::Ordering::Release);
        map
    };
    let r = check_filter_with(&p, rodata(1, true));
    assert!(r.is_ok(), "{r:?}");
    let (e, log) = check_filter_with(&p, rodata(1, false)).unwrap_err();
    assert_eq!(e, Errno::EACCES);
    assert!(log.contains("invalid access to map value"), "{log}");
    // Linux reads only an array map with one element, `array_map_direct_value_addr`. With
    // more elements, a read of a constant offset of a looked up value fails.
    let mut p = ld_imm64(1, BPF_PSEUDO_MAP_FD, 3).to_vec();
    p.extend([
        mov64_reg(2, BPF_REG_FP),
        alu64_imm(BPF_ADD, 2, -4),
        st_mem(BPF_W, 2, 0, 0),
        call(crate::helpers::func::BPF_FUNC_map_lookup_elem),
        jmp_imm(BPF_JEQ, 0, 0, 1),
        ldx_mem(BPF_B, 0, 0, 0),
        mov64_imm(0, 0),
        exit(),
    ]);
    assert!(check_filter_with(&p, rodata(2, false)).is_ok());
    assert_eq!(check_filter_with(&p, rodata(2, true)).map_err(|e| e.0), Err(Errno::ENOTSUPP));
}

/// The start of the programs of the precision tests: r6 = ctx, r0 = the map value, and
/// r1 = skb->len, a scalar that the verifier does not know. If r0 is NULL, the program goes to
/// the instruction `null_exit` (r0 = 0; exit).
fn precision_head(null_exit: usize) -> Vec<BpfInsn> {
    use crate::insn::asm::*;
    let mut p = vec![mov64_reg(6, 1)];
    p.extend(ld_imm64(1, BPF_PSEUDO_MAP_FD, 3));
    p.extend([
        mov64_reg(2, BPF_REG_FP),
        alu64_imm(BPF_ADD, 2, -4),
        st_mem(BPF_W, 2, 0, 0),
        call(crate::helpers::func::BPF_FUNC_map_lookup_elem),
        jmp_imm(BPF_JEQ, 0, 0, null_exit as i16 - 8),
        ldx_mem(BPF_W, 1, 6, 0),
    ]);
    p
}

/// A refused program must stay refused with the pruning. The tests have a scalar that is a
/// constant on each path, and a byte store at r0 + the scalar. With 8 the store is out of the
/// value, with 7 it is in the value. `do_check` goes on the path of the next instruction
/// first, so it keeps the state of the good path at the join, and then the other path comes
/// to the join. If the scalar were not precise in the kept state, the pruning would stop the
/// other path at the join, and the verifier would accept the bad store.
fn assert_precise(prog: impl Fn(i32) -> Vec<BpfInsn>) {
    assert!(check_filter(&prog(7)).is_ok(), "{:?}", check_filter(&prog(7)));
    let (e, log) = check_filter(&prog(8)).expect_err("the store at r0 + 8 is out of the value");
    assert_eq!(e, Errno::EACCES);
    assert!(log.contains("invalid access to map value"), "{log}");
}

#[test]
fn a_pointer_offset_is_precise_at_a_join() {
    use crate::insn::asm::*;
    // 9: r7 = bad; 10: if r1 > 5 goto 12; 11: r7 = 0; 12: r0 += r7 (the join).
    assert_precise(|bad| {
        let mut p = precision_head(14);
        p.extend([
            mov64_imm(7, bad),
            jmp_imm(BPF_JGT, 1, 5, 1),
            mov64_imm(7, 0),
            alu64_reg(BPF_ADD, 0, 7),
            st_mem(BPF_B, 0, 0, 1),
            mov64_imm(0, 0),
            exit(),
        ]);
        p
    });
}

#[test]
fn a_spilled_pointer_offset_is_precise_at_a_join() {
    use crate::insn::asm::*;
    // The scalar is in the stack slot fp-8 at the join 14, so the slot must be precise.
    // 9: r7 = bad; 10: *(u64 *)(fp - 8) = r7; 11: if r1 > 5 goto 14; 12: r7 = 0;
    // 13: *(u64 *)(fp - 8) = r7; 14: r8 = *(u64 *)(fp - 8); 15: r0 += r8.
    assert_precise(|bad| {
        let mut p = precision_head(17);
        p.extend([
            mov64_imm(7, bad),
            stx_mem(BPF_DW, BPF_REG_FP, 7, -8),
            jmp_imm(BPF_JGT, 1, 5, 2),
            mov64_imm(7, 0),
            stx_mem(BPF_DW, BPF_REG_FP, 7, -8),
            ldx_mem(BPF_DW, 8, BPF_REG_FP, -8),
            alu64_reg(BPF_ADD, 0, 8),
            st_mem(BPF_B, 0, 0, 1),
            mov64_imm(0, 0),
            exit(),
        ]);
        p
    });
}

#[test]
fn a_pruned_path_gives_the_precision_to_its_parents() {
    use crate::insn::asm::*;
    // The first path (10 to 13) keeps the state at the join 21 with r7 = 0 precise. The second
    // path (14 to 17) keeps the state at 20 with r7 = 0, and the state at 21 prunes it. The
    // third path (18) comes to 20 with r7 = bad. If the pruning at 21 did not mark r7 precise
    // in the state at 20 (`propagate_precision`), the state at 20 would prune the third path.
    assert_precise(|bad| {
        let mut p = precision_head(23);
        p.extend([
            mov64_imm(7, 0),
            jmp_imm(BPF_JGT, 1, 5, 3),
            mov64_imm(2, 0),
            mov64_imm(2, 0),
            jmp_imm(BPF_JA, 0, 0, 7),
            jmp_imm(BPF_JGT, 1, 9, 3),
            mov64_imm(3, 0),
            mov64_imm(3, 0),
            jmp_imm(BPF_JA, 0, 0, 2),
            mov64_imm(7, bad),
            mov64_imm(3, 0),
            mov64_imm(3, 0),
            alu64_reg(BPF_ADD, 0, 7),
            st_mem(BPF_B, 0, 0, 1),
            mov64_imm(0, 0),
            exit(),
        ]);
        p
    });
}
