# Changelog

This file records each release. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The version numbers follow [Semantic Versioning](https://semver.org/).

## Unreleased

## [0.1.1] (2026-10-23)

This release starts milestone R1. A user process can now have its own address space, and the kernel can run more than one task.

### Added

- Kernel tasks in `rk_frame::task`. A task has a kernel stack of 32 KiB on the heap, with an unmapped page before and after it. `TaskOptions::spawn` makes a task, `yield_now` lets the next task run, `exit` ends the task, and a `WaitQueue` blocks a task until a condition is true. `should_yield` tells a task that runs user code that its time slice of 4 ticks is over. The new `task` boot test runs three tasks in turns and a task that waits in a wait queue.
- The rk-sched crate. It gives rk-frame a round robin scheduler through `inject_scheduler`.
- `rk_frame::vm::VmSpace`, the page table of one user address space. The user half belongs to the address space, and the kernel half is the same in each address space. The address space owns its frames through `Arc<Frame>`, so two address spaces can map the same frame. `read`, `write` and `fill_zero` copy user memory through a software walk, and give a `UserFault` at the first page that is not mapped or not writable. The new `vm` boot test runs a program in two address spaces and examines that each program reads its own data.
- `Frame::read_bytes`, `Frame::write_bytes`, `Frame::fill_zero`, `Frame::copy_from` and `mm::alloc_zeroed_frame`.
- Each `UserContext` keeps the x87 and SSE state and the FS base of its thread. rk-frame turns on SSE at boot, loads the state with `fxrstor64` before the entry to user mode and saves it with `fxsave64` after the exit. `set_fs_base` gives the value for `arch_prctl(ARCH_SET_FS)`. The `syscall` boot test runs two user programs that use SSE registers in turns and examines that each keeps its values.

### Removed

- `rk_frame::user::map_page`. It put user pages in the kernel page table. A user page is now in a `VmSpace`.

## [0.1.0] (2026-10-23)

This release completes milestone R0, the skeleton. `rkc l1 --reference 7.3` passes for x86-64, each system call number gives `ENOSYS`, and CI enforces the unsafe rule.

### Added

- The kernel heap. rk-frame gives the global allocator, so the safe crates can use `Box`, `Vec`, `BTreeMap` and `Arc`. A small object comes from a slab of 16 to 2048 bytes in the direct map. A large object gets its own pages with a guard page after it. The new `heap` boot test examines it.
- A CI job runs `rkc l1 --reference 7.3` of rukernel-compat on each pull request. It compares the generated ABI of each architecture with the uAPI headers that the Linux 7.3 build installs. The job is part of the `ci` check.

## [0.0.4] (2026-10-23)

### Added

- The Linux boot protocol on x86-64. `cargo xtask boot-test` writes a bzImage next to the ELF image. The real mode setup code gets the E820 memory map from the BIOS and goes to the 32 bit entry. The 64 bit entry is 0x200 bytes after it. The kernel reads the command line, the memory map, the initramfs and the ACPI RSDP from `boot_params`.
- The EFI stub. The bzImage has a PE/COFF header, so UEFI firmware can start it as an EFI application. The stub copies the kernel to 1 MiB, reads the command line from the load options and the ACPI RSDP from the configuration table, calls ExitBootServices and goes to the 64 bit entry. The kernel reads the EFI memory map from `boot_params`.
- The `boot` and `mm` boot tests also run with the bzImage, with the BIOS of QEMU and with OVMF. CI installs OVMF.

### Changed

- `BootInfo::push_region` merges an entry with the last entry when the two are adjacent and have the same kind.
- `cargo xtask unsafe` reads a budget for each crate in `xtask/unsafe-allowed.txt` and needs an audit section in `frame/AUDITED.md` for each crate in the list.

## [0.0.3] (2026-10-23)

### Added

- `rk-abigen`, the ABI generator, in `tools/rk-abigen`. `rk-abigen fetch` downloads the Linux 7.3 tarball and checks its SHA-256. `rk-abigen generate` writes the system call tables of x86-64, arm64 and riscv64 into `abi/7.3/` as TOML and into `rk-abi` as Rust.
- `rk_abi::x86_64::syscalls`, `rk_abi::aarch64::syscalls` and `rk_abi::riscv64::syscalls` give the number of each system call and a table of names. `rk_abi::native` is the module of the target.
- `cargo xtask abi` and a CI job run the generator again and fail if the output is not in the tree.
- `rk-abigen` generates the uAPI constants of each architecture: the error numbers, the flags of `open`, `fcntl`, the `*at` calls, `mmap`, `clone`, `sigaction`, `wait4`, `futex` and `poll`, and the clock IDs. It installs the uAPI headers as `make headers_install` does, and clang compiles a probe for each target, as asm-offsets does in Linux. The values are in `abi/7.3/<arch>/constants.toml` and in modules such as `rk_abi::x86_64::open`.
- `rk-abigen` generates the uAPI structures of each architecture, for example `struct stat`, `struct statx`, `struct clone_args`, `struct epoll_event` and `struct new_utsname`. clang gives the layout of each structure. The Rust structures are `#[repr(C)]`, have a field for each padding gap, derive the zerocopy traits and have a compile time check of each offset. They are in `rk_abi::<arch>::types` and in `abi/7.3/<arch>/types.toml`.
- `rk-abi` depends on `zerocopy` 0.8, so that a structure can be copied from user memory with no `unsafe` code.
- User mode on x86-64. `rk_frame::user::UserContext::execute` runs user code until a system call, an exception or an interrupt, and gives the reason. The `syscall` instruction goes to the kernel through LSTAR. The return to user mode is always `iretq`. The TSS has an entry stack for traps from user mode.
- `rk_frame::user::map_page` maps a frame in the user half of the address space.
- The system call table of the kernel. Each number gives `-ENOSYS` in R0.
- The `syscall` boot test. A user program makes each system call number of x86-64 and checks that each one gives `-ENOSYS`.

### Changed

- rk-abigen now generates the `Errno` constants from `<asm/errno.h>`. `Errno` has all the error numbers of Linux, from `EPERM` (1) to `EHWPOISON` (133), and the hand-written list is gone.

### Fixed

- The boot tests use KVM only when the runner can open `/dev/kvm`. Otherwise QEMU uses TCG.
- The license check allows GPL-2.0-only for the crates of this workspace, because they are published now.

## [0.0.2] (2026-10-23)

### Added

- Traps on x86-64. The GDT has the Linux selectors. The TSS has separate stacks for a double fault, an NMI and a machine check. The IDT sends all 256 vectors to one trap handler. An unhandled kernel exception prints an Oops message with the registers and panics.
- An exception table, as in Linux. `rk_frame::trap::probe_read_u64` reads an address and gives an error on a fault, with no panic.
- The `trap` boot test.
- The release workflow publishes `rk-abi`, `rk-frame`, `rk-lib` and `rukernel` to crates.io. The publish script obeys the crates.io rate limits.
- A frame allocator. It is a bitmap of the usable memory in the memory map. `rk_frame::mm::Frame` owns one physical page and gives it back when it is dropped.
- The kernel page tables, with the Linux layout: the direct map at `0xffff888000000000`, the vmalloc range at `0xffffc90000000000` and the kernel image at `0xffffffff80000000`. Text is read only and executable, rodata is read only, and data and bss are writable and not executable. The boot identity map is gone after this step.
- `rk_frame::mm::vmap` maps a frame in the vmalloc range with a guard page after it. `rk_frame::mm::query` and `translate` walk the page tables.
- The `mm` boot test.
- The local APIC in x2APIC mode, or in xAPIC mode when the CPU has no x2APIC. The legacy PIC is masked. The APIC timer is measured against the PIT and interrupts 250 times each second on vector `0xec`, as in Linux.
- `rk_frame::irq` turns interrupts on and off, and `rk_frame::time` gives the tick count and the timer frequency.
- The `timer` boot test.

### Fixed

- The PVH entry clears the bss before the first Rust code runs.

## [0.0.1] (2026-10-23)

### Added

- The design, in `spec/`.
- The workspace skeleton: `rk-frame`, `rk-abi`, `rk-lib` and `xtask`.
- The unsafe rule, the layer rule and the prose rules, as `cargo xtask` checks.
- The CI gate, the security workflows and the release workflow.
- The kernel binary, `rukernel`. It boots on x86-64 under QEMU through the PVH entry, prints the boot log on the serial port and reads the memory map.
- `cargo xtask qemu` and `cargo xtask boot-test`, and a CI job that runs the boot tests.

[0.1.1]: https://github.com/tamnd/rukernel/releases/tag/v0.1.1
[0.1.0]: https://github.com/tamnd/rukernel/releases/tag/v0.1.0
[0.0.4]: https://github.com/tamnd/rukernel/releases/tag/v0.0.4
[0.0.3]: https://github.com/tamnd/rukernel/releases/tag/v0.0.3
[0.0.2]: https://github.com/tamnd/rukernel/releases/tag/v0.0.2
[0.0.1]: https://github.com/tamnd/rukernel/releases/tag/v0.0.1
