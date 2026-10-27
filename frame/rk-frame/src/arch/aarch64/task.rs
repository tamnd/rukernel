//! The context switch between kernel tasks.
//!
//! A task that is not on the CPU has its callee saved registers on its own kernel stack, and its
//! saved stack pointer in its `TaskContext`. Per the procedure call standard of arm64, these are
//! x19 to x29, the link register x30 and the low halves d8 to d15 of v8 to v15. The kernel code
//! uses the SIMD registers, so the switch keeps d8 to d15 too. `switch` stores these registers,
//! saves the stack pointer, loads the stack pointer of the next task and loads its registers. The
//! `ret` then goes to the place where the next task called `switch`.
//!
//! A new task has a stack that looks like the stack of a task that called `switch`. Its link
//! register is `rk_task_entry`, which calls the start function of the task.
//!
//! The user registers, with TPIDR_EL0 and the FP and SIMD state of user mode, are in the
//! `UserContext` of the thread. `user::enter` loads them, so the switch does not keep them.

/// The saved stack pointer of a task that is not on the CPU.
#[derive(Debug, Default)]
pub(crate) struct TaskContext {
    sp: u64,
}

/// The size of the frame that `rk_task_switch` stores: x19 to x30 and d8 to d15.
const SWITCH_FRAME: usize = 20 * 8;
/// The offset of x30 in the frame.
const LR_OFFSET: usize = 11 * 8;

core::arch::global_asm!(
    r#"
    .section .text.rk_task, "ax"
    .global rk_task_switch
rk_task_switch:                     // x0: the context to save, x1: the stack pointer to load
    sub     sp, sp, #{frame}
    stp     x19, x20, [sp, #0]
    stp     x21, x22, [sp, #16]
    stp     x23, x24, [sp, #32]
    stp     x25, x26, [sp, #48]
    stp     x27, x28, [sp, #64]
    stp     x29, x30, [sp, #80]
    stp     d8, d9, [sp, #96]
    stp     d10, d11, [sp, #112]
    stp     d12, d13, [sp, #128]
    stp     d14, d15, [sp, #144]
    mov     x2, sp
    str     x2, [x0]
    mov     sp, x1
    ldp     x19, x20, [sp, #0]
    ldp     x21, x22, [sp, #16]
    ldp     x23, x24, [sp, #32]
    ldp     x25, x26, [sp, #48]
    ldp     x27, x28, [sp, #64]
    ldp     x29, x30, [sp, #80]
    ldp     d8, d9, [sp, #96]
    ldp     d10, d11, [sp, #112]
    ldp     d12, d13, [sp, #128]
    ldp     d14, d15, [sp, #144]
    add     sp, sp, #{frame}
    ret

    .global rk_task_entry
rk_task_entry:                      // the stack pointer is 16 byte aligned here
    mov     x29, xzr
    bl      {start}
    brk     #1
"#,
    frame = const SWITCH_FRAME,
    start = sym crate::task::task_start,
);

unsafe extern "C" {
    fn rk_task_switch(save: *mut u64, load: u64);
    fn rk_task_entry();
}

impl TaskContext {
    /// Makes the context of a new task with a stack that ends at `top`. The first `switch` to it
    /// goes to `task_start` on this stack.
    ///
    /// # Panics
    ///
    /// If `top` is not 16 byte aligned.
    pub(crate) fn new(top: usize) -> Self {
        assert!(top.is_multiple_of(16), "the stack top {top:#x} is not aligned");
        let frame = top - SWITCH_FRAME;
        let entry = rk_task_entry as *const () as u64;
        for off in (0..SWITCH_FRAME).step_by(8) {
            let value = if off == LR_OFFSET { entry } else { 0 };
            // SAFETY: the caller gives the top of a stack that it owns and that no code uses yet.
            // The frame is the last `SWITCH_FRAME` bytes below the top.
            unsafe { ((frame + off) as *mut u64).write(value) };
        }
        Self { sp: frame as u64 }
    }
}

/// Saves the registers of this task in `from` and loads the registers of the task of `to`. The
/// function returns when a later switch loads `from` again.
///
/// # Safety
///
/// Interrupts are off. `to` is the context of a task that is not on the CPU. Its stack and its
/// context stay alive until the task is on the CPU again. The same is true for `from`.
pub(crate) unsafe fn switch(from: *mut TaskContext, to: *const TaskContext) {
    // SAFETY: the caller gives contexts that live, and no other reference to them exists.
    let save = unsafe { &raw mut (*from).sp };
    // SAFETY: as above.
    let load = unsafe { (*to).sp };
    // SAFETY: `load` was saved by `rk_task_switch` or made by `TaskContext::new`, so its stack has
    // the frame that `rk_task_switch` loads. `save` points into a context that lives.
    unsafe { rk_task_switch(save, load) };
}
