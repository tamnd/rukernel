# The audited crates

Each crate in this file can contain `unsafe` code. Each other crate of the kernel has `#![forbid(unsafe_code)]` at its root, per spec/23-package-layout.md section 23.3.

`cargo xtask unsafe` checks the rule. It reads the list and the budget of each crate from `xtask/unsafe-allowed.txt`, and it finds a section in this file for each crate on the list. It also prints the lines of code and the `unsafe` blocks of each crate. Each release gives these numbers in its notes.

To add a crate, open an issue with the label `area/frame`. The issue gives the reason that the crate cannot be safe, the owner, the budget in lines of code and the plan for the audit. Then add a section here and a line to `xtask/unsafe-allowed.txt` in the same pull request.

## rk-frame

The trusted base of the kernel. It contains the boot code, the trap and interrupt entry, the page tables, the frame allocator, the entry to user mode, the locks and the device access. This code touches the hardware, so it cannot be safe Rust.

- Owner: tamnd.
- Budget: 25,000 lines of code, per spec/02-the-goal.md section 2.4.
- Rules: each `unsafe` block has a `// SAFETY:` comment, and each block has one unsafe operation. Clippy checks both rules. The interfaces that rk-frame gives to the other crates are safe.
- Audit: each pull request that changes rk-frame gets a review of each new or changed `unsafe` block against its `// SAFETY:` comment.
- The vDSO in `frame/rk-frame/vdso` is user code, not kernel code. It is in rk-frame because it reads the data page that rk-frame writes. The same rules and the same audit apply to it.
