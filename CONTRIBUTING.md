# Contributing

This document tells you how to make a change. The design is in [`spec/`](spec/). Read the design document for the subsystem before you change it.

## Before you start

The project is at milestone R0. The design is complete and the code is a skeleton. Each milestone has a tracking issue with the label `kind/milestone`. Select an item from the tracking issue of the current milestone. Write a comment on the issue before you start the work. Work on a later milestone usually waits for the earlier milestones.

If a part of the design is wrong, open an issue with the label `kind/open-question`. Give the document and the section.

## Run the checks

```
cargo xtask ci
```

This command runs the checks of the CI gate. The cheapest checks run first. You can also run each check alone:

```
cargo xtask unsafe       # the unsafe rule
cargo xtask layers       # the layer rule
cargo xtask style        # the prose rules
cargo xtask targets      # the kernel crates on the three bare metal targets
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## The rules for a change

**A change to behavior has a test that fails without the change.** If you cannot write this test, tell us in the pull request. We will find the correct test with you.

**The unsafe rule.** Only `rk-frame` and the crates in `xtask/unsafe-allowed.txt` can contain `unsafe` code. Each `unsafe` block has a `// SAFETY:` comment. Clippy checks this. To add a crate to the list, open an issue with the label `area/frame`. Give the reason, the owner and the size budget. [`spec/23-package-layout.md`](spec/23-package-layout.md) section 23.3 gives the procedure.

**The layer rule.** A crate depends only on crates in its layer or a lower layer. `xtask/layers.txt` gives the layers. Section 23.2 of the same document gives the reasons.

**The ABI is generated.** Do not write a system call number, a structure layout or a uAPI constant by hand. Change `rk-abigen` or its input. Then run `cargo run -p rk-abigen -- fetch` one time and `cargo run -p rk-abigen -- generate`, and commit the files in `abi/` and `core/rk-abi/src/generated/`. `cargo xtask abi` does the same steps and fails if the output is not in the tree.

**A behavior difference from Linux is a bug.** If Linux and rukernel give different results, fix rukernel. If the difference is correct, add an entry to the register in `rukernel-compat` and give the reason.

**A performance claim has a command that reproduces it.** Give the median of ten runs and the interquartile range. Give the machine. Show the losses with the wins.

**A new dependency is a decision.** Give the reason in the pull request. The kernel is GPL-2.0-only. Thus a dependency must have a license that GPL-2.0 can carry. `cargo deny check` examines this.

## Style

**Rust.** `cargo fmt` sets the layout. A comment tells why, not what. Each public item has documentation. If a decision in the code comes from the design, give the document and the section, for example `// spec/07-memory.md section 7.3`.

**Prose.** This rule applies to documents, commit messages, issues and pull requests. Use plain English. Use short sentences. Use the active voice. Do not use em dashes or en dashes. Do not use horizontal rules. Use a heading. Do not break a sentence across lines. Write one paragraph on one line. `cargo xtask style` examines the dashes and the rules.

## Commits and pull requests

Write the commit subject in the imperative mood. Start with the crate name, for example `rk-mm: batch the COW copy in fork`. Keep the subject at 72 characters or less. In the body, tell what was wrong and why the change is correct.

A pull request contains one change. The CI gate must pass. A maintainer merges with squash or rebase.

## Releases

A maintainer makes a release. The steps are:

1. Change the workspace version in `Cargo.toml`, and the version of each path dependency in `[workspace.dependencies]`. Move the `Unreleased` section of `CHANGELOG.md` to a section for the new version.
2. Merge that change, then push a tag `vX.Y.Z` on main.
3. The release workflow runs the gate on the tag. Then it publishes the GitHub release with a source archive and publishes the crates to crates.io.

A patch release `v0.x.y` comes at intervals during a milestone. A minor release `v0.x.0` comes when a milestone is complete.

crates.io limits the rate of publishes. A new crate has a burst of 5 and then 1 each 10 minutes. `.github/scripts/publish-crates.sh` waits and tries again, and it skips each version that is already on crates.io. Thus you can run the job again after a failure.
