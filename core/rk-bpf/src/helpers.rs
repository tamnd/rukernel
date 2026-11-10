//! The helper functions, kernel/bpf/helpers.c and net/core/filter.c of Linux.
//!
//! Each helper has a `struct bpf_func_proto`: the types of its arguments and of its result. The
//! verifier checks a call with the proto, and the interpreter runs the helper.
#![allow(non_upper_case_globals)]

use crate::map::MapEnv;
use crate::prog::prog_type::*;

/// What the helpers need of the current task and the machine.
pub trait HelperEnv {
    /// The number of possible CPUs and the CPU of the caller.
    fn map_env(&self) -> MapEnv;
    /// The nanoseconds since boot, `ktime_get_ns` of Linux.
    fn ktime_get_ns(&self) -> u64;
    /// The thread group ID in the high 32 bits and the thread ID in the low 32 bits. A run
    /// without a task gives `-EINVAL`, as `bpf_get_current_pid_tgid` of Linux.
    fn current_pid_tgid(&self) -> Option<u64>;
    /// The group ID in the high 32 bits and the user ID in the low 32 bits.
    fn current_uid_gid(&self) -> Option<u64>;
    /// The ID of the cgroup of the current task, as `cgroup_id` of Linux.
    fn current_cgroup_id(&self) -> u64;
}

/// The function IDs of the helpers, `enum bpf_func_id` of Linux.
#[allow(missing_docs)]
pub mod func {
    pub const BPF_FUNC_map_lookup_elem: i32 = 1;
    pub const BPF_FUNC_map_update_elem: i32 = 2;
    pub const BPF_FUNC_map_delete_elem: i32 = 3;
    pub const BPF_FUNC_ktime_get_ns: i32 = 5;
    pub const BPF_FUNC_get_prandom_u32: i32 = 7;
    pub const BPF_FUNC_get_smp_processor_id: i32 = 8;
    pub const BPF_FUNC_tail_call: i32 = 12;
    pub const BPF_FUNC_get_current_pid_tgid: i32 = 14;
    pub const BPF_FUNC_get_current_uid_gid: i32 = 15;
    pub const BPF_FUNC_skb_load_bytes: i32 = 26;
    pub const BPF_FUNC_get_numa_node_id: i32 = 42;
    pub const BPF_FUNC_get_current_cgroup_id: i32 = 80;
    pub const BPF_FUNC_ktime_get_boot_ns: i32 = 125;
}

/// The type of an argument, `enum bpf_arg_type` of Linux.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArgType {
    /// No argument.
    DontCare,
    /// A map, `ARG_CONST_MAP_PTR`.
    ConstMapPtr,
    /// A key of the map of the first argument, `ARG_PTR_TO_MAP_KEY`.
    PtrToMapKey,
    /// A value of the map of the first argument, `ARG_PTR_TO_MAP_VALUE`.
    PtrToMapValue,
    /// Memory that the helper writes, `ARG_PTR_TO_UNINIT_MEM`. The next argument is its size.
    PtrToUninitMem,
    /// The size of the memory of the argument before, `ARG_CONST_SIZE`. It is not zero.
    ConstSize,
    /// The context, `ARG_PTR_TO_CTX`.
    PtrToCtx,
    /// Any scalar, `ARG_ANYTHING`.
    Anything,
}

/// The type of the result, `enum bpf_return_type` of Linux.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetType {
    /// A scalar, `RET_INTEGER`.
    Integer,
    /// A value of the map of the first argument or NULL, `RET_PTR_TO_MAP_VALUE_OR_NULL`.
    PtrToMapValueOrNull,
    /// No result, `RET_VOID`. R0 is not initialized after the call.
    Void,
}

/// The proto of a helper, `struct bpf_func_proto` of Linux.
#[derive(Clone, Copy, Debug)]
pub struct BpfFuncProto {
    /// The name, for the log.
    pub name: &'static str,
    /// The result.
    pub ret_type: RetType,
    /// The five arguments.
    pub arg_type: [ArgType; 5],
}

const fn proto(name: &'static str, ret_type: RetType, args: &[ArgType]) -> BpfFuncProto {
    let mut arg_type = [ArgType::DontCare; 5];
    let mut i = 0;
    while i < args.len() {
        arg_type[i] = args[i];
        i += 1;
    }
    BpfFuncProto { name, ret_type, arg_type }
}

use ArgType::*;
use RetType::*;
use func::*;

/// `bpf_map_lookup_elem_proto`.
const MAP_LOOKUP_ELEM: BpfFuncProto =
    proto("map_lookup_elem", PtrToMapValueOrNull, &[ConstMapPtr, PtrToMapKey]);
/// `bpf_map_update_elem_proto`.
const MAP_UPDATE_ELEM: BpfFuncProto =
    proto("map_update_elem", Integer, &[ConstMapPtr, PtrToMapKey, PtrToMapValue, Anything]);
/// `bpf_map_delete_elem_proto`.
const MAP_DELETE_ELEM: BpfFuncProto =
    proto("map_delete_elem", Integer, &[ConstMapPtr, PtrToMapKey]);
/// `bpf_skb_load_bytes_proto`.
const SKB_LOAD_BYTES: BpfFuncProto =
    proto("skb_load_bytes", Integer, &[PtrToCtx, Anything, PtrToUninitMem, ConstSize]);

/// The proto of the helper `func_id` for a program of the type `prog_type`, as
/// `bpf_base_func_proto` and the `get_func_proto` of the type in Linux. `bpf_capable` and
/// `perfmon_capable` tell the capabilities of the loader. A helper that the program cannot call
/// gives `None`.
pub fn get_func_proto(prog_type: u32, func_id: i32, bpf_capable: bool) -> Option<BpfFuncProto> {
    let p = match func_id {
        BPF_FUNC_map_lookup_elem => MAP_LOOKUP_ELEM,
        BPF_FUNC_map_update_elem => MAP_UPDATE_ELEM,
        BPF_FUNC_map_delete_elem => MAP_DELETE_ELEM,
        // `bpf_tail_call_proto`. The interpreter runs the call, as `JMP_TAIL_CALL` of Linux.
        BPF_FUNC_tail_call => proto("tail_call", Void, &[PtrToCtx, ConstMapPtr, Anything]),
        BPF_FUNC_get_prandom_u32 => proto("get_prandom_u32", Integer, &[]),
        BPF_FUNC_get_smp_processor_id => proto("get_smp_processor_id", Integer, &[]),
        BPF_FUNC_get_numa_node_id => proto("get_numa_node_id", Integer, &[]),
        BPF_FUNC_ktime_get_ns => proto("ktime_get_ns", Integer, &[]),
        BPF_FUNC_ktime_get_boot_ns => proto("ktime_get_boot_ns", Integer, &[]),
        BPF_FUNC_get_current_pid_tgid => proto("get_current_pid_tgid", Integer, &[]),
        BPF_FUNC_get_current_uid_gid => proto("get_current_uid_gid", Integer, &[]),
        // The helpers after the check of `CAP_BPF` in `bpf_base_func_proto`.
        BPF_FUNC_get_current_cgroup_id if bpf_capable => {
            proto("get_current_cgroup_id", Integer, &[])
        }
        // `sk_filter_func_proto` and `cg_skb_func_proto`.
        BPF_FUNC_skb_load_bytes
            if matches!(prog_type, BPF_PROG_TYPE_SOCKET_FILTER | BPF_PROG_TYPE_CGROUP_SKB) =>
        {
            SKB_LOAD_BYTES
        }
        _ => return None,
    };
    Some(p)
}

/// The state of `bpf_user_rnd_u32` of Linux.
static RND_STATE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// A pseudo-random number, `bpf_user_rnd_u32` of Linux. It is not for cryptography.
pub fn bpf_user_rnd_u32(seed: u64) -> u32 {
    use core::sync::atomic::Ordering;
    let mut s = RND_STATE.load(Ordering::Relaxed);
    if s == 0 {
        s = seed | 1;
    }
    // xorshift64*.
    s ^= s >> 12;
    s ^= s << 25;
    s ^= s >> 27;
    RND_STATE.store(s, Ordering::Relaxed);
    (s.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 32) as u32
}
