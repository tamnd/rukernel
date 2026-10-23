# Security policy

## Supported versions

The project is before 1.0. Fixes go on the default branch only. After 1.0, this section will give a support period for each release.

## Report a vulnerability

Use the private vulnerability report of GitHub. Go to the Security tab of this repository and select "Report a vulnerability". Do not open a public issue for a problem that an attacker can use.

We send an answer in seven days or less. If you get no answer in seven days, write a public issue that asks for an answer. Do not describe the problem in that issue.

## What is in scope

A kernel is a security boundary. These problems are in scope:

- Memory unsafety from any system call, ioctl, file system image, network packet or device input.
- A path that lets a process get privileges that Linux does not give it in the same configuration.
- A difference from Linux in a permission check, a capability check, a namespace check or an LSM hook.
- Information from the kernel or from another process that a process can read and must not read.
- A hang or unlimited memory use that an unprivileged process can cause.
- A mistake in a Verus specification of `rk-frame` that makes a proof incorrect.

A crash in the code of `rk-frame` is the most serious kind of problem in this project. All other code is safe Rust. Thus memory unsafety must start in `rk-frame`, in the compiler or in the hardware.

## What we do

We find the cause, make a fix on a private branch, and release the fix with an advisory. The advisory tells what the problem was and which versions it affects. We give credit to the reporter, unless the reporter does not want it.
