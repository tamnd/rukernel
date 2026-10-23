//! The context switch between kernel tasks.
//!
//! A task that is not on the CPU has its callee saved registers on its own kernel stack, and its
//! saved stack pointer in its `TaskContext`. `switch` pushes these registers, saves the stack
//! pointer, loads the stack pointer of the next task and pops its registers. The `ret` then goes to
//! the place where the next task called `switch`.
//!
//! A new task has a stack that looks like the stack of a task that called `switch`. Its return
//! address is `rk_task_entry`, which calls the start function of the task.

/// The saved stack pointer of a task that is not on the CPU.
#[derive(Debug, Default)]
pub(crate) struct TaskContext {
    rsp: u64,
}

core::arch::global_asm!(
    r#"
    .section .text.rk_task, "ax"
    .global rk_task_switch
rk_task_switch:                     # rdi: the context to save, rsi: the stack pointer to load
    pushq %rbp
    pushq %rbx
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    movq %rsp, (%rdi)
    movq %rsi, %rsp
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rbx
    popq %rbp
    ret

    .global rk_task_entry
rk_task_entry:                      # the stack pointer is 16 byte aligned here
    xorl %ebp, %ebp
    call {start}
    ud2
"#,
    start = sym crate::task::task_start,
    options(att_syntax)
);

unsafe extern "C" {
    fn rk_task_switch(save: *mut u64, load: u64);
    fn rk_task_entry();
}

/// The number of words that `rk_task_switch` pops before its `ret`, and the return address.
const SWITCH_FRAME: usize = 7;

impl TaskContext {
    /// Makes the context of a new task with a stack that ends at `top`. The first `switch` to it
    /// goes to `task_start` on this stack.
    ///
    /// # Panics
    ///
    /// If `top` is not 16 byte aligned.
    pub(crate) fn new(top: usize) -> Self {
        assert!(top.is_multiple_of(16), "the stack top {top:#x} is not aligned");
        let frame = (top - SWITCH_FRAME * 8) as *mut u64;
        let entry = rk_task_entry as *const () as u64;
        for i in 0..SWITCH_FRAME {
            let value = if i == SWITCH_FRAME - 1 { entry } else { 0 };
            // SAFETY: the caller gives the top of a stack that it owns and that no code uses yet.
            // The frame is the last `SWITCH_FRAME` words below the top.
            unsafe { frame.add(i).write(value) };
        }
        Self { rsp: frame as u64 }
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
    // SAFETY: the caller gives contexts that live. `to` was saved by `rk_task_switch` or made by
    // `TaskContext::new`, so its stack has the frame that `rk_task_switch` pops.
    unsafe { rk_task_switch(&raw mut (*from).rsp, (*to).rsp) };
}
