// rk-abigen generated this file from Linux 7.3, from <linux/futex.h>.
// Do not edit it. Change rk-abigen and run it again.

//! The operations and flags of `futex`.

/// `FUTEX2_SIZE_U8` from `<linux/futex.h>`.
pub const FUTEX2_SIZE_U8: u32 = 0;
/// If (oldval == CMPARG) wake.
pub const FUTEX_OP_CMP_EQ: u32 = 0;
/// (int \*)UADDR2 = OPARG;.
pub const FUTEX_OP_SET: u32 = 0;
/// `FUTEX_WAIT` from `<linux/futex.h>`.
pub const FUTEX_WAIT: u32 = 0;
/// `FUTEX2_SIZE_U16` from `<linux/futex.h>`.
pub const FUTEX2_SIZE_U16: u32 = 1;
/// (int \*)UADDR2 += OPARG;.
pub const FUTEX_OP_ADD: u32 = 1;
/// If (oldval != CMPARG) wake.
pub const FUTEX_OP_CMP_NE: u32 = 1;
/// `FUTEX_ROBUST_MOD_MASK` from `<linux/futex.h>`.
pub const FUTEX_ROBUST_MOD_MASK: u32 = 1;
/// `FUTEX_ROBUST_MOD_PI` from `<linux/futex.h>`.
pub const FUTEX_ROBUST_MOD_PI: u32 = 1;
/// `FUTEX_WAKE` from `<linux/futex.h>`.
pub const FUTEX_WAKE: u32 = 1;
/// `FUTEX2_SIZE_U32` from `<linux/futex.h>`.
pub const FUTEX2_SIZE_U32: u32 = 2;
/// Historical accident :-(.
pub const FUTEX_32: u32 = 2;
/// `FUTEX_FD` from `<linux/futex.h>`.
pub const FUTEX_FD: u32 = 2;
/// If (oldval \< CMPARG) wake.
pub const FUTEX_OP_CMP_LT: u32 = 2;
/// (int \*)UADDR2 |= OPARG;.
pub const FUTEX_OP_OR: u32 = 2;
/// `FUTEX2_SIZE_MASK` from `<linux/futex.h>`.
pub const FUTEX2_SIZE_MASK: u32 = 3;
/// `FUTEX2_SIZE_U64` from `<linux/futex.h>`.
pub const FUTEX2_SIZE_U64: u32 = 3;
/// (int \*)UADDR2 &= ~OPARG;.
pub const FUTEX_OP_ANDN: u32 = 3;
/// If (oldval \<= CMPARG) wake.
pub const FUTEX_OP_CMP_LE: u32 = 3;
/// `FUTEX_REQUEUE` from `<linux/futex.h>`.
pub const FUTEX_REQUEUE: u32 = 3;
/// `FUTEX2_NUMA` from `<linux/futex.h>`.
pub const FUTEX2_NUMA: u32 = 4;
/// `FUTEX_CMP_REQUEUE` from `<linux/futex.h>`.
pub const FUTEX_CMP_REQUEUE: u32 = 4;
/// If (oldval \> CMPARG) wake.
pub const FUTEX_OP_CMP_GT: u32 = 4;
/// (int \*)UADDR2 ^= OPARG;.
pub const FUTEX_OP_XOR: u32 = 4;
/// If (oldval \>= CMPARG) wake.
pub const FUTEX_OP_CMP_GE: u32 = 5;
/// `FUTEX_WAKE_OP` from `<linux/futex.h>`.
pub const FUTEX_WAKE_OP: u32 = 5;
/// `FUTEX_LOCK_PI` from `<linux/futex.h>`.
pub const FUTEX_LOCK_PI: u32 = 6;
/// `FUTEX_UNLOCK_PI` from `<linux/futex.h>`.
pub const FUTEX_UNLOCK_PI: u32 = 7;
/// `FUTEX2_MPOL` from `<linux/futex.h>`.
pub const FUTEX2_MPOL: u32 = 8;
/// Use (1 \<\< OPARG) instead of OPARG.
pub const FUTEX_OP_OPARG_SHIFT: u32 = 8;
/// `FUTEX_TRYLOCK_PI` from `<linux/futex.h>`.
pub const FUTEX_TRYLOCK_PI: u32 = 8;
/// `FUTEX_WAIT_BITSET` from `<linux/futex.h>`.
pub const FUTEX_WAIT_BITSET: u32 = 9;
/// `FUTEX_WAKE_BITSET` from `<linux/futex.h>`.
pub const FUTEX_WAKE_BITSET: u32 = 10;
/// `FUTEX_WAIT_REQUEUE_PI` from `<linux/futex.h>`.
pub const FUTEX_WAIT_REQUEUE_PI: u32 = 11;
/// `FUTEX_CMP_REQUEUE_PI` from `<linux/futex.h>`.
pub const FUTEX_CMP_REQUEUE_PI: u32 = 12;
/// `FUTEX_LOCK_PI2` from `<linux/futex.h>`.
pub const FUTEX_LOCK_PI2: u32 = 13;
/// The same value as `FUTEX_PRIVATE_FLAG`.
pub const FUTEX2_PRIVATE: u32 = 128;
/// `FUTEX_PRIVATE_FLAG` from `<linux/futex.h>`.
pub const FUTEX_PRIVATE_FLAG: u32 = 128;
/// `FUTEX_WAITV_MAX` from `<linux/futex.h>`.
pub const FUTEX_WAITV_MAX: u32 = 128;
/// `FUTEX_WAIT_PRIVATE` from `<linux/futex.h>`.
pub const FUTEX_WAIT_PRIVATE: u32 = 128;
/// `FUTEX_WAKE_PRIVATE` from `<linux/futex.h>`.
pub const FUTEX_WAKE_PRIVATE: u32 = 129;
/// `FUTEX_REQUEUE_PRIVATE` from `<linux/futex.h>`.
pub const FUTEX_REQUEUE_PRIVATE: u32 = 131;
/// `FUTEX_CMP_REQUEUE_PRIVATE` from `<linux/futex.h>`.
pub const FUTEX_CMP_REQUEUE_PRIVATE: u32 = 132;
/// `FUTEX_WAKE_OP_PRIVATE` from `<linux/futex.h>`.
pub const FUTEX_WAKE_OP_PRIVATE: u32 = 133;
/// `FUTEX_LOCK_PI_PRIVATE` from `<linux/futex.h>`.
pub const FUTEX_LOCK_PI_PRIVATE: u32 = 134;
/// `FUTEX_UNLOCK_PI_PRIVATE` from `<linux/futex.h>`.
pub const FUTEX_UNLOCK_PI_PRIVATE: u32 = 135;
/// `FUTEX_TRYLOCK_PI_PRIVATE` from `<linux/futex.h>`.
pub const FUTEX_TRYLOCK_PI_PRIVATE: u32 = 136;
/// `FUTEX_WAIT_BITSET_PRIVATE` from `<linux/futex.h>`.
pub const FUTEX_WAIT_BITSET_PRIVATE: u32 = 137;
/// `FUTEX_WAKE_BITSET_PRIVATE` from `<linux/futex.h>`.
pub const FUTEX_WAKE_BITSET_PRIVATE: u32 = 138;
/// `FUTEX_WAIT_REQUEUE_PI_PRIVATE` from `<linux/futex.h>`.
pub const FUTEX_WAIT_REQUEUE_PI_PRIVATE: u32 = 139;
/// `FUTEX_CMP_REQUEUE_PI_PRIVATE` from `<linux/futex.h>`.
pub const FUTEX_CMP_REQUEUE_PI_PRIVATE: u32 = 140;
/// `FUTEX_LOCK_PI2_PRIVATE` from `<linux/futex.h>`.
pub const FUTEX_LOCK_PI2_PRIVATE: u32 = 141;
/// `FUTEX_CLOCK_REALTIME` from `<linux/futex.h>`.
pub const FUTEX_CLOCK_REALTIME: u32 = 0x100;
/// `FUTEX_ROBUST_UNLOCK` from `<linux/futex.h>`.
pub const FUTEX_ROBUST_UNLOCK: u32 = 0x200;
/// `FUTEX_UNLOCK_WAKE_LIST64` from `<linux/futex.h>`.
pub const FUTEX_UNLOCK_WAKE_LIST64: u32 = 0x201;
/// `FUTEX_UNLOCK_PI_LIST64` from `<linux/futex.h>`.
pub const FUTEX_UNLOCK_PI_LIST64: u32 = 0x207;
/// `FUTEX_UNLOCK_BITSET_LIST64` from `<linux/futex.h>`.
pub const FUTEX_UNLOCK_BITSET_LIST64: u32 = 0x20a;
/// `FUTEX_UNLOCK_WAKE_LIST64_PRIVATE` from `<linux/futex.h>`.
pub const FUTEX_UNLOCK_WAKE_LIST64_PRIVATE: u32 = 0x281;
/// `FUTEX_UNLOCK_PI_LIST64_PRIVATE` from `<linux/futex.h>`.
pub const FUTEX_UNLOCK_PI_LIST64_PRIVATE: u32 = 0x287;
/// `FUTEX_UNLOCK_BITSET_LIST64_PRIVATE` from `<linux/futex.h>`.
pub const FUTEX_UNLOCK_BITSET_LIST64_PRIVATE: u32 = 0x28a;
/// `FUTEX_ROBUST_LIST32` from `<linux/futex.h>`.
pub const FUTEX_ROBUST_LIST32: u32 = 0x400;
/// `FUTEX_UNLOCK_WAKE_LIST32` from `<linux/futex.h>`.
pub const FUTEX_UNLOCK_WAKE_LIST32: u32 = 0x601;
/// `FUTEX_UNLOCK_PI_LIST32` from `<linux/futex.h>`.
pub const FUTEX_UNLOCK_PI_LIST32: u32 = 0x607;
/// `FUTEX_UNLOCK_BITSET_LIST32` from `<linux/futex.h>`.
pub const FUTEX_UNLOCK_BITSET_LIST32: u32 = 0x60a;
/// `FUTEX_UNLOCK_WAKE_LIST32_PRIVATE` from `<linux/futex.h>`.
pub const FUTEX_UNLOCK_WAKE_LIST32_PRIVATE: u32 = 0x681;
/// `FUTEX_UNLOCK_PI_LIST32_PRIVATE` from `<linux/futex.h>`.
pub const FUTEX_UNLOCK_PI_LIST32_PRIVATE: u32 = 0x687;
/// `FUTEX_UNLOCK_BITSET_LIST32_PRIVATE` from `<linux/futex.h>`.
pub const FUTEX_UNLOCK_BITSET_LIST32_PRIVATE: u32 = 0x68a;
/// `ROBUST_LIST_LIMIT` from `<linux/futex.h>`.
pub const ROBUST_LIST_LIMIT: u32 = 0x800;
/// `FUTEX_TID_MASK` from `<linux/futex.h>`.
pub const FUTEX_TID_MASK: u32 = 0x3fff_ffff;
/// `FUTEX_OWNER_DIED` from `<linux/futex.h>`.
pub const FUTEX_OWNER_DIED: u32 = 0x4000_0000;
/// `FUTEX_WAITERS` from `<linux/futex.h>`.
pub const FUTEX_WAITERS: u32 = 0x8000_0000;
/// `FUTEX_CMD_MASK` from `<linux/futex.h>`.
pub const FUTEX_CMD_MASK: u32 = 0xffff_f87f;
/// `FUTEX_BITSET_MATCH_ANY` from `<linux/futex.h>`.
pub const FUTEX_BITSET_MATCH_ANY: u32 = 0xffff_ffff;
/// `FUTEX_NO_NODE` from `<linux/futex.h>`.
pub const FUTEX_NO_NODE: u32 = 0xffff_ffff;
