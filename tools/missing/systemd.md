# The missing files of systemd

The files under /proc and /sys that the `systemd` boot test looks for and that rukernel does not have, from a boot with `rk.missing=1`. `report.py` made this file on 2026-11-07. PID, TID and FD stand for a number, and cpuN for the number of a CPU.

The boot ends in the state `running`. Some of these names are also missing on Linux in the same QEMU machine: `/proc/vz` and `/proc/xen`, which systemd looks for to find the hypervisor, `/sys/fs/selinux` and `/sys/fs/smackfs` without these security modules, `/sys/class/tpmrm` without a TPM, `/sys/firmware/efi` on a BIOS boot, and the `loop` directory of a loop device that has no file.

30 files are missing.

| File | Programs | Lookups | Linux |
| --- | --- | --- | --- |
| `/proc/PID/net/ip_tables_names` | `systemd` | 1 | [net/core/net-procfs.c](https://github.com/torvalds/linux/blob/v7.3/net/core/net-procfs.c) |
| `/proc/kcore` | `systemd` | 1 | [fs/proc/kcore.c](https://github.com/torvalds/linux/blob/v7.3/fs/proc/kcore.c) |
| `/proc/kmsg` | `(d-logind)` | 2 | [fs/proc/kmsg.c](https://github.com/torvalds/linux/blob/v7.3/fs/proc/kmsg.c) |
| `/proc/sys/fs/binfmt_misc` | `systemd`, `systemd-shutdow` | 3 | [fs/binfmt_misc.c](https://github.com/torvalds/linux/blob/v7.3/fs/binfmt_misc.c) |
| `/proc/sys/kernel/printk_devkmsg` | `systemd` | 2 | [kernel/sysctl.c](https://github.com/torvalds/linux/blob/v7.3/kernel/sysctl.c) |
| `/proc/vz` | `systemd-tmpfile`, `journalctl`, `systemd-random-`, `systemd-user-se`, `systemd-debug-g`, `systemd-fstab-g`, `systemd-getty-g`, `systemd-gpt-aut`, `systemd-hiberna`, `systemd-rc-loca`, `systemd-run-gen`, `systemd-ssh-gen`, `systemd-system-`, `systemd-sysv-ge`, `systemd-tpm2-ge`, `systemd-modules`, `systemd-remount`, `systemd-journal`, `systemd-sysctl`, `systemd-sysuser`, `systemd-update-`, `systemd-logind`, `(rk-check)`, `systemd-shutdow` | 29 | [fs/proc/root.c](https://github.com/torvalds/linux/blob/v7.3/fs/proc/root.c) |
| `/proc/xen` | `systemd` | 1 | [fs/proc/root.c](https://github.com/torvalds/linux/blob/v7.3/fs/proc/root.c) |
| `/sys/class/misc/autofs` | `systemd` | 1 | [drivers/base/class.c](https://github.com/torvalds/linux/blob/v7.3/drivers/base/class.c) |
| `/sys/class/tpmrm` | `systemd`, `systemd-tpm2-ge` | 2 | [drivers/char/tpm/tpm-sysfs.c](https://github.com/torvalds/linux/blob/v7.3/drivers/char/tpm/tpm-sysfs.c) |
| `/sys/devices/virtual/block/loop0/loop` | `systemd-shutdow` | 1 | [fs/sysfs/](https://github.com/torvalds/linux/blob/v7.3/fs/sysfs/) |
| `/sys/devices/virtual/block/loop1/loop` | `systemd-shutdow` | 1 | [fs/sysfs/](https://github.com/torvalds/linux/blob/v7.3/fs/sysfs/) |
| `/sys/devices/virtual/block/loop2/loop` | `systemd-shutdow` | 1 | [fs/sysfs/](https://github.com/torvalds/linux/blob/v7.3/fs/sysfs/) |
| `/sys/devices/virtual/block/loop3/loop` | `systemd-shutdow` | 1 | [fs/sysfs/](https://github.com/torvalds/linux/blob/v7.3/fs/sysfs/) |
| `/sys/devices/virtual/block/loop4/loop` | `systemd-shutdow` | 1 | [fs/sysfs/](https://github.com/torvalds/linux/blob/v7.3/fs/sysfs/) |
| `/sys/devices/virtual/block/loop5/loop` | `systemd-shutdow` | 1 | [fs/sysfs/](https://github.com/torvalds/linux/blob/v7.3/fs/sysfs/) |
| `/sys/devices/virtual/block/loop6/loop` | `systemd-shutdow` | 1 | [fs/sysfs/](https://github.com/torvalds/linux/blob/v7.3/fs/sysfs/) |
| `/sys/devices/virtual/block/loop7/loop` | `systemd-shutdow` | 1 | [fs/sysfs/](https://github.com/torvalds/linux/blob/v7.3/fs/sysfs/) |
| `/sys/devices/virtual/tty/console/active` | `systemd`, `systemd-getty-g` | 2 | [fs/sysfs/](https://github.com/torvalds/linux/blob/v7.3/fs/sysfs/) |
| `/sys/firmware/acpi` | `systemd` | 2 | [drivers/acpi/sysfs.c](https://github.com/torvalds/linux/blob/v7.3/drivers/acpi/sysfs.c) |
| `/sys/firmware/dmi/entries` | `systemd` | 2 | [drivers/firmware/](https://github.com/torvalds/linux/blob/v7.3/drivers/firmware/) |
| `/sys/firmware/efi` | `systemd`, `systemd-gpt-aut`, `systemd-tpm2-ge` | 6 | [drivers/firmware/efi/efi.c](https://github.com/torvalds/linux/blob/v7.3/drivers/firmware/efi/efi.c) |
| `/sys/firmware/qemu_fw_cfg` | `systemd` | 2 | [drivers/firmware/](https://github.com/torvalds/linux/blob/v7.3/drivers/firmware/) |
| `/sys/fs/pstore` | `systemd` | 4 | [fs/pstore/inode.c](https://github.com/torvalds/linux/blob/v7.3/fs/pstore/inode.c) |
| `/sys/fs/selinux` | `9`, `mount`, `systemd-tmpfile`, `systemctl`, `journalctl`, `systemd-random-`, `systemd-user-se`, `umount`, `systemd`, `systemd-debug-g`, `systemd-fstab-g`, `systemd-getty-g`, `systemd-gpt-aut`, `systemd-hiberna`, `systemd-rc-loca`, `systemd-run-gen`, `systemd-ssh-gen`, `systemd-system-`, `systemd-sysv-ge`, `systemd-tpm2-ge`, `systemd-modules`, `systemd-remount`, `systemd-journal`, `systemd-sysctl`, `systemd-sysuser`, `systemd-update-`, `dbus-daemon`, `systemd-logind`, `systemd-shutdow` | 76 | [security/selinux/selinuxfs.c](https://github.com/torvalds/linux/blob/v7.3/security/selinux/selinuxfs.c) |
| `/sys/fs/smackfs` | `9`, `mount`, `systemd-tmpfile`, `systemd`, `systemd-user-se`, `systemd-sysuser`, `systemd-update-`, `systemd-logind` | 51 | [fs/sysfs/mount.c](https://github.com/torvalds/linux/blob/v7.3/fs/sysfs/mount.c) |
| `/sys/module/apparmor` | `(mount)`, `(modprobe)`, `dbus-daemon`, `(tmpfiles)`, `(urnalctl)`, `(dom-seed)`, `(sessions)`, `(umount)`, `systemd`, `(les-load)`, `(journald)`, `(mount-fs)`, `(d-sysctl)`, `(sysusers)`, `(ldconfig)`, `(ate-done)`, `(s-daemon)`, `(d-logind)`, `(rk-check)` | 38 | [kernel/params.c](https://github.com/torvalds/linux/blob/v7.3/kernel/params.c) |
| `/sys/module/compression` | `modprobe`, `systemd`, `systemd-modules` | 6 | [kernel/params.c](https://github.com/torvalds/linux/blob/v7.3/kernel/params.c) |
| `/sys/module/ipv6` | `systemd` | 1 | [kernel/params.c](https://github.com/torvalds/linux/blob/v7.3/kernel/params.c) |
| `/sys/module/virtiofs` | `systemd` | 1 | [kernel/params.c](https://github.com/torvalds/linux/blob/v7.3/kernel/params.c) |
| `/sys/module/vt` | `systemd` | 2 | [kernel/params.c](https://github.com/torvalds/linux/blob/v7.3/kernel/params.c) |
