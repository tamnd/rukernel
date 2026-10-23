## What this changes

<!-- Give the problem first. Then give the change. Do not repeat the diff. -->

## Why

<!-- If this closes an issue, write `Closes #N`. If this is part of a milestone, give the milestone. -->

## How it was verified

<!-- Give the test that fails without this change. If no test fails, tell why. -->

## Checklist

- [ ] `cargo xtask ci` passes on my machine
- [ ] A change to behavior has a test that fails without the change
- [ ] The change adds no `unsafe` code outside `rk-frame`, or the issue for the new audited crate is linked
- [ ] A behavior difference from Linux is fixed, or it has an entry in the `rukernel-compat` register
- [ ] A performance claim has the command, the median of ten runs, the interquartile range and the machine
- [ ] A new dependency has a reason and a license that GPL-2.0 can carry
- [ ] The prose follows the rules: plain English, no em dashes, no horizontal rules, one paragraph on one line
